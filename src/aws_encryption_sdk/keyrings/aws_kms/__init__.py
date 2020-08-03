# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Keyring for use with AWS Key Management Service (KMS).

.. versionadded:: 1.5.0

"""
import logging

import attr
import six
from attr.validators import deep_iterable, instance_of, is_callable, optional

from aws_encryption_sdk.exceptions import DecryptKeyError, EncryptKeyError
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.internal.validators import value_is_not_a_string
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.keyrings.multi import MultiKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, KeyringTraceFlag, MasterKeyInfo, RawDataKey

from .client_suppliers import DefaultClientSupplier

from .client_suppliers import ClientSupplier  # noqa - only used in docstring params; this confuses flake8

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Iterable, Union  # noqa pylint: disable=unused-import

    from .client_suppliers import ClientSupplierType  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("AwsKmsKeyring", "KEY_NAMESPACE")

_LOGGER = logging.getLogger(__name__)
_GENERATE_FLAGS = {KeyringTraceFlag.GENERATED_DATA_KEY}
_ENCRYPT_FLAGS = {KeyringTraceFlag.ENCRYPTED_DATA_KEY, KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT}
_DECRYPT_FLAGS = {KeyringTraceFlag.DECRYPTED_DATA_KEY, KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT}

#: Key namespace used for all encrypted data keys created by the KMS keyring.
KEY_NAMESPACE = "aws-kms"


@attr.s
class AwsKmsKeyring(Keyring):
    """Keyring that uses AWS Key Management Service (KMS) Customer Master Keys (CMKs) to manage wrapping keys.

    Set ``generator_key_id`` to require that the keyring use that CMK to generate the data key.
    If you do not set ``generator_key_id``, the keyring will not generate a data key.

    Set ``key_ids`` to specify additional CMKs that the keyring will use to encrypt the data key.

    The keyring will attempt to use any CMKs
    identified by CMK ARN in either ``generator_key_id`` or ``key_ids`` on decrypt.

    You can identify CMKs by any `valid key ID`_ for the keyring to use on encrypt,
    but for the keyring to attempt to use them on decrypt
    you MUST specify the CMK ARN.

    If you specify ``is_discovery=True`` the keyring will be a KMS discovery keyring,
    doing nothing on encrypt and attempting to decrypt any AWS KMS-encrypted data key on decrypt.

    .. note::

        You must either set ``is_discovery=True`` or provide key IDs.

    You can use the :class:`ClientSupplier` to customize behavior further,
    such as to provide different credentials for different regions
    or to restrict which regions are allowed.

    See the `AWS KMS Keyring specification`_ for more details.

    .. _AWS KMS Keyring specification:
       https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/kms-keyring.md
    .. _valid key ID:
       https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html#API_GenerateDataKey_RequestSyntax
    .. _discovery mode:
       https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#kms-keyring-discovery

    .. versionadded:: 1.5.0

    :param ClientSupplier client_supplier: Client supplier that provides AWS KMS clients (optional)
    :param bool is_discovery: Should this be a discovery keyring (optional)
    :param str generator_key_id: Key ID of AWS KMS CMK to use when generating data keys (optional)
    :param List[str] key_ids: Key IDs that will be used to encrypt and decrypt data keys (optional)
    :param List[str] grant_tokens: AWS KMS grant tokens to include in requests (optional)
    """

    _client_supplier = attr.ib(default=attr.Factory(DefaultClientSupplier), validator=is_callable())
    _is_discovery = attr.ib(default=False, validator=instance_of(bool))
    _generator_key_id = attr.ib(default=None, validator=optional(instance_of(six.string_types)))
    _key_ids = attr.ib(
        default=attr.Factory(tuple),
        validator=(deep_iterable(member_validator=instance_of(six.string_types)), value_is_not_a_string),
    )
    _grant_tokens = attr.ib(
        default=attr.Factory(tuple),
        validator=(deep_iterable(member_validator=instance_of(six.string_types)), value_is_not_a_string),
    )

    def __attrs_post_init__(self):
        """Configure internal keyring."""
        key_ids_provided = self._generator_key_id is not None or self._key_ids
        both = key_ids_provided and self._is_discovery
        neither = not key_ids_provided and not self._is_discovery

        if both:
            raise TypeError("is_discovery cannot be True if key IDs are provided")

        if neither:
            raise TypeError("is_discovery cannot be False if no key IDs are provided")

        if self._is_discovery:
            self._inner_keyring = _AwsKmsDiscoveryKeyring(
                client_supplier=self._client_supplier, grant_tokens=self._grant_tokens
            )
            return

        if self._generator_key_id is None:
            generator_keyring = None
        else:
            generator_keyring = _AwsKmsSingleCmkKeyring(
                key_id=self._generator_key_id, client_supplier=self._client_supplier, grant_tokens=self._grant_tokens
            )

        child_keyrings = [
            _AwsKmsSingleCmkKeyring(
                key_id=key_id, client_supplier=self._client_supplier, grant_tokens=self._grant_tokens
            )
            for key_id in self._key_ids
        ]

        self._inner_keyring = MultiKeyring(generator=generator_keyring, children=child_keyrings)

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key using generator keyring
        and encrypt it using any available wrapping key in any child keyring.

        :param EncryptionMaterials encryption_materials: Encryption materials for keyring to modify.
        :returns: Optionally modified encryption materials.
        :rtype: EncryptionMaterials
        :raises EncryptKeyError: if unable to encrypt data key.
        """
        return self._inner_keyring.on_encrypt(encryption_materials=encryption_materials)

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param DecryptionMaterials decryption_materials: Decryption materials for keyring to modify.
        :param List[EncryptedDataKey] encrypted_data_keys: List of encrypted data keys.
        :returns: Optionally modified decryption materials.
        :rtype: DecryptionMaterials
        """
        return self._inner_keyring.on_decrypt(
            decryption_materials=decryption_materials, encrypted_data_keys=encrypted_data_keys
        )


@attr.s
class _AwsKmsSingleCmkKeyring(Keyring):
    """AWS KMS keyring that only works with a single AWS KMS CMK.

    This keyring should never be used directly.
    It should only ever be used internally by :class:`AwsKmsKeyring`.

    .. versionadded:: 1.5.0

    :param str key_id: CMK key ID
    :param ClientSupplier client_supplier: Client supplier to use when asking for clients
    :param List[str] grant_tokens: AWS KMS grant tokens to include in requests (optional)
    """

    _key_id = attr.ib(validator=instance_of(six.string_types))
    _client_supplier = attr.ib(validator=is_callable())
    _grant_tokens = attr.ib(
        default=attr.Factory(tuple),
        validator=(deep_iterable(member_validator=instance_of(six.string_types)), value_is_not_a_string),
    )

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        trace_info = MasterKeyInfo(provider_id=KEY_NAMESPACE, key_info=self._key_id)
        new_materials = encryption_materials
        try:
            if new_materials.data_encryption_key is None:
                plaintext_key, encrypted_key = _do_aws_kms_generate_data_key(
                    client_supplier=self._client_supplier,
                    key_name=self._key_id,
                    encryption_context=new_materials.encryption_context,
                    algorithm=new_materials.algorithm,
                    grant_tokens=self._grant_tokens,
                )
                new_materials = new_materials.with_data_encryption_key(
                    data_encryption_key=plaintext_key,
                    keyring_trace=KeyringTrace(wrapping_key=trace_info, flags=_GENERATE_FLAGS),
                )
            else:
                encrypted_key = _do_aws_kms_encrypt(
                    client_supplier=self._client_supplier,
                    key_name=self._key_id,
                    plaintext_data_key=new_materials.data_encryption_key,
                    encryption_context=new_materials.encryption_context,
                    grant_tokens=self._grant_tokens,
                )
        except Exception:  # pylint: disable=broad-except
            # We intentionally WANT to catch all exceptions here
            message = "Unable to generate or encrypt data key using {}".format(trace_info)
            _LOGGER.exception(message)
            raise EncryptKeyError(message)

        return new_materials.with_encrypted_data_key(
            encrypted_data_key=encrypted_key, keyring_trace=KeyringTrace(wrapping_key=trace_info, flags=_ENCRYPT_FLAGS)
        )

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        new_materials = decryption_materials

        for edk in encrypted_data_keys:
            if new_materials.data_encryption_key is not None:
                return new_materials

            if (
                edk.key_provider.provider_id == KEY_NAMESPACE
                and edk.key_provider.key_info.decode("utf-8") == self._key_id
            ):
                new_materials = _try_aws_kms_decrypt(
                    client_supplier=self._client_supplier,
                    decryption_materials=new_materials,
                    grant_tokens=self._grant_tokens,
                    encrypted_data_key=edk,
                )

        return new_materials


@attr.s
class _AwsKmsDiscoveryKeyring(Keyring):
    """AWS KMS discovery keyring that will attempt to decrypt any AWS KMS encrypted data key.

    This keyring should never be used directly.
    It should only ever be used internally by :class:`AwsKmsKeyring`.

    .. versionadded:: 1.5.0

    :param ClientSupplier client_supplier: Client supplier to use when asking for clients
    :param List[str] grant_tokens: AWS KMS grant tokens to include in requests (optional)
    """

    _client_supplier = attr.ib(validator=is_callable())
    _grant_tokens = attr.ib(
        default=attr.Factory(tuple),
        validator=(deep_iterable(member_validator=instance_of(six.string_types)), value_is_not_a_string),
    )

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        new_materials = decryption_materials

        for edk in encrypted_data_keys:
            if new_materials.data_encryption_key is not None:
                return new_materials

            if edk.key_provider.provider_id == KEY_NAMESPACE:
                new_materials = _try_aws_kms_decrypt(
                    client_supplier=self._client_supplier,
                    decryption_materials=new_materials,
                    grant_tokens=self._grant_tokens,
                    encrypted_data_key=edk,
                )

        return new_materials


def _try_aws_kms_decrypt(client_supplier, decryption_materials, grant_tokens, encrypted_data_key):
    # type: (ClientSupplierType, DecryptionMaterials, Iterable[str], EncryptedDataKey) -> DecryptionMaterials
    """Attempt to call ``kms:Decrypt`` and return the resulting plaintext data key.

    Any errors encountered are caught and logged.

    .. versionadded:: 1.5.0

    """
    try:
        plaintext_key = _do_aws_kms_decrypt(
            client_supplier=client_supplier,
            key_name=encrypted_data_key.key_provider.key_info.decode("utf-8"),
            encrypted_data_key=encrypted_data_key,
            encryption_context=decryption_materials.encryption_context,
            grant_tokens=grant_tokens,
        )
    except Exception:  # pylint: disable=broad-except
        # We intentionally WANT to catch all exceptions here
        _LOGGER.exception("Unable to decrypt encrypted data key from %s", encrypted_data_key.key_provider)
        return decryption_materials

    return decryption_materials.with_data_encryption_key(
        data_encryption_key=plaintext_key,
        keyring_trace=KeyringTrace(wrapping_key=encrypted_data_key.key_provider, flags=_DECRYPT_FLAGS),
    )


def _do_aws_kms_decrypt(client_supplier, key_name, encrypted_data_key, encryption_context, grant_tokens):
    # type: (ClientSupplierType, str, EncryptedDataKey, Dict[str, str], Iterable[str]) -> RawDataKey
    """Attempt to call ``kms:Decrypt`` and return the resulting plaintext data key.

    Any errors encountered are passed up the chain without comment.

    .. versionadded:: 1.5.0

    """
    region = _region_from_key_id(encrypted_data_key.key_provider.key_info.decode("utf-8"))
    client = client_supplier(region)
    response = client.decrypt(
        CiphertextBlob=encrypted_data_key.encrypted_data_key,
        EncryptionContext=encryption_context,
        GrantTokens=grant_tokens,
    )
    response_key_id = response["KeyId"]
    if response_key_id != key_name:
        raise DecryptKeyError(
            "Decryption results from AWS KMS are for an unexpected key ID!"
            " actual '{actual}' != expected '{expected}'".format(actual=response_key_id, expected=key_name)
        )
    return RawDataKey(
        key_provider=MasterKeyInfo(provider_id=KEY_NAMESPACE, key_info=response_key_id), data_key=response["Plaintext"]
    )


def _do_aws_kms_encrypt(client_supplier, key_name, plaintext_data_key, encryption_context, grant_tokens):
    # type: (ClientSupplierType, str, RawDataKey, Dict[str, str], Iterable[str]) -> EncryptedDataKey
    """Attempt to call ``kms:Encrypt`` and return the resulting encrypted data key.

    Any errors encountered are passed up the chain without comment.
    """
    region = _region_from_key_id(key_name)
    client = client_supplier(region)
    response = client.encrypt(
        KeyId=key_name,
        Plaintext=plaintext_data_key.data_key,
        EncryptionContext=encryption_context,
        GrantTokens=grant_tokens,
    )
    return EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id=KEY_NAMESPACE, key_info=response["KeyId"]),
        encrypted_data_key=response["CiphertextBlob"],
    )


def _do_aws_kms_generate_data_key(client_supplier, key_name, encryption_context, algorithm, grant_tokens):
    # type: (ClientSupplierType, str, Dict[str, str], AlgorithmSuite, Iterable[str]) -> (RawDataKey, EncryptedDataKey)
    """Attempt to call ``kms:GenerateDataKey`` and return the resulting plaintext and encrypted data keys.

    Any errors encountered are passed up the chain without comment.

    .. versionadded:: 1.5.0

    """
    region = _region_from_key_id(key_name)
    client = client_supplier(region)
    response = client.generate_data_key(
        KeyId=key_name,
        NumberOfBytes=algorithm.kdf_input_len,
        EncryptionContext=encryption_context,
        GrantTokens=grant_tokens,
    )
    provider = MasterKeyInfo(provider_id=KEY_NAMESPACE, key_info=response["KeyId"])
    plaintext_key = RawDataKey(key_provider=provider, data_key=response["Plaintext"])
    encrypted_key = EncryptedDataKey(key_provider=provider, encrypted_data_key=response["CiphertextBlob"])
    return plaintext_key, encrypted_key


def _region_from_key_id(key_id):
    # type: (str) -> Union[None, str]
    """Attempt to determine the region from the key ID.

    If the region cannot be found, ``None`` is returned instead.

    .. versionadded:: 1.5.0

    """
    parts = key_id.split(":", 4)
    try:
        return parts[3]
    except IndexError:
        return None
