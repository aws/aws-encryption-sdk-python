# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Keyring for use with :class:`MasterKey`s and :class:`MasterKeyProvider`s."""
import attr
from attr.validators import instance_of

from aws_encryption_sdk.exceptions import (
    DecryptKeyError,
    IncorrectMasterKeyError,
    InvalidCryptographicMaterialsError,
    MasterKeyProviderError,
    UnknownIdentityError,
)
from aws_encryption_sdk.identifiers import EncryptionKeyType
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyProvider
from aws_encryption_sdk.key_providers.kms import KMSMasterKey
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, KeyringTraceFlag, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable, Set  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("MasterKeyProviderKeyring",)


def _signs_encryption_context(master_key):
    # type: (MasterKey) -> bool
    if isinstance(master_key, KMSMasterKey):
        return True

    if isinstance(master_key, RawMasterKey):
        if master_key.config.wrapping_key.wrapping_key_type is EncryptionKeyType.SYMMETRIC:
            return True

    return False


def _generate_flags():
    # type: () -> Set[KeyringTraceFlag]
    """Build the keyring trace flags for a generate data key operation.

    :return: Set of keyring trace flags
    :rtype: set of :class:`KeyringTraceFlag`
    """
    return {KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY}


def _encrypt_flags(master_key):
    # type: (MasterKey) -> Set[KeyringTraceFlag]
    """Build the keyring trace flags for an encrypt data key operation.

    :param MasterKey master_key: Master key that encrypted the key
    :return: Set of keyring trace flags
    :rtype: set of :class:`KeyringTraceFlag`
    """
    flags = {KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY}
    if _signs_encryption_context(master_key):
        flags.add(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)
    return flags


def _decrypt_flags(master_key):
    # type: (MasterKey) -> Set[KeyringTraceFlag]
    """Build the keyring trace flags for a decrypt data key operation.

    :param MasterKey master_key: Master key that decrypted the key
    :return: Set of keyring trace flags
    :rtype: set of :class:`KeyringTraceFlag`
    """
    flags = {KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY}
    if _signs_encryption_context(master_key):
        flags.add(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
    return flags


@attr.s
class MasterKeyProviderKeyring(Keyring):
    """Keyring compatibility layer for use with master key providers.

    .. versionadded:: 1.5.0

    :param MasterKeyProvider master_key_provider: Master key provider to use
    """

    _master_key_provider = attr.ib(validator=instance_of(MasterKeyProvider))

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param encryption_materials: Encryption materials for the keyring to modify.
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Optionally modified encryption materials.
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises NotImplementedError: if method is not implemented
        """
        primary_master_key, master_keys = self._master_key_provider.master_keys_for_encryption(
            encryption_context=encryption_materials.encryption_context, plaintext_rostream=None, plaintext_length=None,
        )
        if not master_keys:
            raise MasterKeyProviderError("No Master Keys available from Master Key Provider")
        if primary_master_key not in master_keys:
            raise MasterKeyProviderError("Primary Master Key not in provided Master Keys")

        if encryption_materials.data_encryption_key is not None:
            # Because the default CMM used to require that the primary MKP was the generator,
            #  this keyring cannot accept encryption materials that already have a data key.
            raise InvalidCryptographicMaterialsError(
                "Unable to use master keys with encryption materials that already contain a data key."
                " You are probably trying to mix master key providers and keyrings."
                " If you want to do that, the master key provider MUST be the generator."
            )

        data_encryption_key = primary_master_key.generate_data_key(
            algorithm=encryption_materials.algorithm, encryption_context=encryption_materials.encryption_context,
        )

        encryption_materials.add_data_encryption_key(
            data_encryption_key=RawDataKey(
                data_key=data_encryption_key.data_key, key_provider=data_encryption_key.key_provider,
            ),
            keyring_trace=KeyringTrace(wrapping_key=primary_master_key.key_provider, flags=_generate_flags(),),
        )
        encryption_materials.add_encrypted_data_key(
            encrypted_data_key=EncryptedDataKey(
                key_provider=data_encryption_key.key_provider,
                encrypted_data_key=data_encryption_key.encrypted_data_key,
            ),
            keyring_trace=KeyringTrace(
                wrapping_key=primary_master_key.key_provider, flags=_encrypt_flags(primary_master_key),
            ),
        )

        # Go through all of the other master keys and encrypt
        for child in master_keys:
            if child is primary_master_key:
                # The additional master keys returned by MasterKeyProvider.master_keys_for_encryption
                # can include the primary master key.
                # We already have the encrypted data key from the primary, so skip it.
                continue

            encrypted_data_key = child.encrypt_data_key(
                data_key=data_encryption_key,
                algorithm=encryption_materials.algorithm,
                encryption_context=encryption_materials.encryption_context,
            )
            encryption_materials.add_encrypted_data_key(
                encrypted_data_key=EncryptedDataKey(
                    key_provider=encrypted_data_key.key_provider,
                    encrypted_data_key=encrypted_data_key.encrypted_data_key,
                ),
                keyring_trace=KeyringTrace(wrapping_key=child.key_provider, flags=_encrypt_flags(child)),
            )

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: Decryption materials for the keyring to modify.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :param encrypted_data_keys: List of encrypted data keys.
        :type: Iterable of :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Optionally modified decryption materials.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :raises NotImplementedError: if method is not implemented
        """
        # If the plaintext data key is set, just return.
        if decryption_materials.data_encryption_key is not None:
            return decryption_materials

        # Use the master key provider to decrypt.
        try:
            decrypted_data_key = self._master_key_provider.decrypt_data_key_from_list(
                encrypted_data_keys=encrypted_data_keys,
                algorithm=decryption_materials.algorithm,
                encryption_context=decryption_materials.encryption_context,
            )
        # MasterKeyProvider.decrypt_data_key throws DecryptKeyError
        # but MasterKey.decrypt_data_key throws IncorrectMasterKeyError
        except (IncorrectMasterKeyError, DecryptKeyError):
            # Don't fail here for master key providers.
            # The default CMM will fail if no keyrings can decrypt.
            return decryption_materials

        # Find the master key object that was used for decryption
        #   This is important because we need the key ID for the trace,
        #   not the provider info, which is what is in the returned data key.
        try:
            decrypting_master_key = list(self._master_key_provider.master_keys_for_data_key(decrypted_data_key))[0]
        except IndexError:
            raise UnknownIdentityError(
                "Unable to locate master key for {}".format(repr(decrypted_data_key.key_provider))
            )

        # Add the plaintext data to the decryption materials, along with a trace.
        decryption_materials.add_data_encryption_key(
            data_encryption_key=RawDataKey(
                key_provider=decrypted_data_key.key_provider, data_key=decrypted_data_key.data_key,
            ),
            keyring_trace=KeyringTrace(
                wrapping_key=decrypting_master_key.key_provider, flags=_decrypt_flags(decrypting_master_key),
            ),
        )

        return decryption_materials
