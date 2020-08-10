# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Resources required for Raw Keyrings."""
import logging
import os

import attr
import six
from attr.validators import in_, instance_of, optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from aws_encryption_sdk.exceptions import EncryptKeyError, GenerateKeyError
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import EncryptedData, WrappingKey
from aws_encryption_sdk.internal.formatting.deserialize import deserialize_wrapped_key
from aws_encryption_sdk.internal.formatting.serialize import serialize_raw_master_key_prefix, serialize_wrapped_key
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("RawAESKeyring", "RawRSAKeyring")
_LOGGER = logging.getLogger(__name__)


def _generate_data_key(
    encryption_materials,  # type: EncryptionMaterials
    key_provider,  # type: MasterKeyInfo
):
    # type: (...) -> EncryptionMaterials
    """Generates plaintext data key for the keyring.

    :param EncryptionMaterials encryption_materials: Encryption materials for the keyring to modify.
    :param MasterKeyInfo key_provider: Information about the key in the keyring.
    :rtype: EncryptionMaterials
    :returns: Encryption materials containing a data encryption key
    """
    # Check if encryption materials contain data encryption key
    if encryption_materials.data_encryption_key is not None:
        raise TypeError("Data encryption key already exists.")

    # Generate data key
    try:
        plaintext_data_key = os.urandom(encryption_materials.algorithm.kdf_input_len)
    except Exception:  # pylint: disable=broad-except
        error_message = "Unable to generate data encryption key."
        _LOGGER.exception(error_message)
        raise GenerateKeyError("Unable to generate data encryption key.")

    # plaintext_data_key to RawDataKey
    data_encryption_key = RawDataKey(key_provider=key_provider, data_key=plaintext_data_key)

    return encryption_materials.with_data_encryption_key(
        data_encryption_key=data_encryption_key,
    )


@attr.s
class RawAESKeyring(Keyring):
    """Generate an instance of Raw AES Keyring which encrypts using AES-GCM algorithm using wrapping key provided as a
    byte array

    .. versionadded:: 2.0.0

    :param str key_namespace: String defining the keyring.
    :param bytes key_name: Key ID
    :param bytes wrapping_key: Encryption key with which to wrap plaintext data key.

    .. note::

        Only one wrapping key can be specified in a Raw AES Keyring
    """

    key_namespace = attr.ib(validator=instance_of(six.string_types))
    key_name = attr.ib(validator=instance_of(six.binary_type))
    _wrapping_key = attr.ib(repr=False, validator=instance_of(six.binary_type))

    def __attrs_post_init__(self):
        # type: () -> None
        """Prepares initial values not handled by attrs."""
        key_size_to_wrapping_algorithm = {
            wrapper.algorithm.kdf_input_len: wrapper
            for wrapper in (
                WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
                WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
                WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            )
        }

        try:
            self._wrapping_algorithm = key_size_to_wrapping_algorithm[len(self._wrapping_key)]
        except KeyError:
            raise ValueError(
                "Invalid wrapping key length. Must be one of {} bytes.".format(
                    sorted(key_size_to_wrapping_algorithm.keys())
                )
            )

        self._key_provider = MasterKeyInfo(provider_id=self.key_namespace, key_info=self.key_name)

        self._wrapping_key_structure = WrappingKey(
            wrapping_algorithm=self._wrapping_algorithm,
            wrapping_key=self._wrapping_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )

        self._key_info_prefix = self._get_key_info_prefix(
            key_namespace=self.key_namespace, key_name=self.key_name, wrapping_key=self._wrapping_key_structure
        )

    @staticmethod
    def _get_key_info_prefix(key_namespace, key_name, wrapping_key):
        # type: (str, bytes, WrappingKey) -> six.binary_type
        """Helper function to get key info prefix

        :param str key_namespace: String defining the keyring.
        :param bytes key_name: Key ID
        :param WrappingKey wrapping_key: Encryption key with which to wrap plaintext data key.
        :return: Serialized key_info prefix
        :rtype: bytes
        """
        key_info_prefix = serialize_raw_master_key_prefix(
            RawMasterKey(provider_id=key_namespace, key_id=key_name, wrapping_key=wrapping_key)
        )
        return key_info_prefix

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key if not present and encrypt it using any available wrapping key

        :param EncryptionMaterials encryption_materials: Encryption materials for the keyring to modify
        :returns: Encryption materials containing data key and encrypted data key
        :rtype: EncryptionMaterials
        """
        new_materials = encryption_materials

        if new_materials.data_encryption_key is None:
            # Get encryption materials with a new data key.
            new_materials = _generate_data_key(encryption_materials=new_materials, key_provider=self._key_provider)

        try:
            # Encrypt data key
            encrypted_wrapped_key = self._wrapping_key_structure.encrypt(
                plaintext_data_key=new_materials.data_encryption_key.data_key,
                encryption_context=new_materials.encryption_context,
            )

            # EncryptedData to EncryptedDataKey
            encrypted_data_key = serialize_wrapped_key(
                key_provider=self._key_provider,
                wrapping_algorithm=self._wrapping_algorithm,
                wrapping_key_id=self.key_name,
                encrypted_wrapped_key=encrypted_wrapped_key,
            )
        except Exception:  # pylint: disable=broad-except
            error_message = "Raw AES keyring unable to encrypt data key"
            _LOGGER.exception(error_message)
            raise EncryptKeyError(error_message)

        return new_materials.with_encrypted_data_key(encrypted_data_key=encrypted_data_key)

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param DecryptionMaterials decryption_materials: Decryption materials for the keyring to modify
        :param List[EncryptedDataKey] encrypted_data_keys: List of encrypted data keys
        :returns: Decryption materials that MAY include a plaintext data key
        :rtype: DecryptionMaterials
        """
        new_materials = decryption_materials

        if new_materials.data_encryption_key is not None:
            return new_materials

        # Decrypt data key
        expected_key_info_len = len(self._key_info_prefix) + self._wrapping_algorithm.algorithm.iv_len
        for key in encrypted_data_keys:

            if (
                key.key_provider.provider_id != self._key_provider.provider_id
                or len(key.key_provider.key_info) != expected_key_info_len
                or not key.key_provider.key_info.startswith(self._key_info_prefix)
            ):
                continue

            # Wrapped EncryptedDataKey to deserialized EncryptedData
            encrypted_wrapped_key = deserialize_wrapped_key(
                wrapping_algorithm=self._wrapping_algorithm, wrapping_key_id=self.key_name, wrapped_encrypted_key=key
            )

            # EncryptedData to raw key string
            try:
                plaintext_data_key = self._wrapping_key_structure.decrypt(
                    encrypted_wrapped_data_key=encrypted_wrapped_key,
                    encryption_context=new_materials.encryption_context,
                )

            except Exception:  # pylint: disable=broad-except
                # We intentionally WANT to catch all exceptions here
                error_message = "Raw AES Keyring unable to decrypt data key"
                _LOGGER.exception(error_message)
                # The Raw AES keyring MUST evaluate every encrypted data key
                # until it either succeeds or runs out of encrypted data keys.
                continue

            # Update decryption materials
            data_encryption_key = RawDataKey(key_provider=self._key_provider, data_key=plaintext_data_key)

            return new_materials.with_data_encryption_key(data_encryption_key=data_encryption_key)

        return new_materials


@attr.s
class RawRSAKeyring(Keyring):
    """Generate an instance of Raw RSA Keyring which performs asymmetric encryption and decryption using public
    and private keys provided

    .. versionadded:: 2.0.0

    :param str key_namespace: String defining the keyring ID
    :param bytes key_name: Key ID
    :param cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey private_wrapping_key:
        Private encryption key with which to wrap plaintext data key (optional)
    :param cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey public_wrapping_key:
        Public encryption key with which to wrap plaintext data key (optional)
    :param WrappingAlgorithm wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key
    :param MasterKeyInfo key_provider: Complete information about the key in the keyring

    .. note::

        At least one of public wrapping key or private wrapping key must be provided.
    """

    key_namespace = attr.ib(validator=instance_of(six.string_types))
    key_name = attr.ib(validator=instance_of(six.binary_type))
    _wrapping_algorithm = attr.ib(
        repr=False,
        validator=in_(
            (
                WrappingAlgorithm.RSA_PKCS1,
                WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
                WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
                WrappingAlgorithm.RSA_OAEP_SHA384_MGF1,
                WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
            )
        ),
    )
    _private_wrapping_key = attr.ib(default=None, repr=False, validator=optional(instance_of(RSAPrivateKey)))
    _public_wrapping_key = attr.ib(default=None, repr=False, validator=optional(instance_of(RSAPublicKey)))

    def __attrs_post_init__(self):
        # type: () -> None
        """Prepares initial values not handled by attrs."""
        self._key_provider = MasterKeyInfo(provider_id=self.key_namespace, key_info=self.key_name)

        if self._public_wrapping_key is None and self._private_wrapping_key is None:
            raise TypeError("At least one of public key or private key must be provided.")

        if self._public_wrapping_key is not None and self._private_wrapping_key is not None:
            derived_public_key = self._private_wrapping_key.public_key()
            # We cannot compare the public key objects directly.
            # Instead, extract their numbers and compare those.
            if derived_public_key.public_numbers() != self._public_wrapping_key.public_numbers():
                raise ValueError("Private and public wrapping keys MUST be from the same keypair.")

    @classmethod
    def from_pem_encoding(
        cls,
        key_namespace,  # type: str
        key_name,  # type: bytes
        wrapping_algorithm,  # type: WrappingAlgorithm
        public_encoded_key=None,  # type: bytes
        private_encoded_key=None,  # type: bytes
        password=None,  # type: bytes
    ):
        # type: (...) -> RawRSAKeyring
        """Generate a Raw RSA keyring using PEM Encoded public and private keys

        :param str key_namespace: String defining the keyring ID
        :param bytes key_name: Key ID
        :param WrappingAlgorithm wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key
        :param bytes public_encoded_key: PEM encoded public key (optional)
        :param bytes private_encoded_key: PEM encoded private key (optional)
        :param bytes password: Password to load private key (optional)
        :return: :class:`RawRSAKeyring` constructed using required parameters
        """
        loaded_private_wrapping_key = loaded_public_wrapping_key = None
        if private_encoded_key is not None:
            loaded_private_wrapping_key = serialization.load_pem_private_key(
                data=private_encoded_key, password=password, backend=default_backend()
            )
        if public_encoded_key is not None:
            loaded_public_wrapping_key = serialization.load_pem_public_key(
                data=public_encoded_key, backend=default_backend()
            )

        return cls(
            key_namespace=key_namespace,
            key_name=key_name,
            wrapping_algorithm=wrapping_algorithm,
            private_wrapping_key=loaded_private_wrapping_key,
            public_wrapping_key=loaded_public_wrapping_key,
        )

    @classmethod
    def from_der_encoding(
        cls,
        key_namespace,  # type: str
        key_name,  # type: bytes
        wrapping_algorithm,  # type: WrappingAlgorithm
        public_encoded_key=None,  # type: bytes
        private_encoded_key=None,  # type: bytes
        password=None,  # type: bytes
    ):
        # type: (...) -> RawRSAKeyring
        """Generate a raw RSA keyring using DER Encoded public and private keys

        :param str key_namespace: String defining the keyring ID
        :param bytes key_name: Key ID
        :param WrappingAlgorithm wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key
        :param bytes public_encoded_key: DER encoded public key (optional)
        :param bytes private_encoded_key: DER encoded private key (optional)
        :param bytes password: Password to load private key (optional)
        :return: :class:`RawRSAKeyring` constructed using required parameters
        """
        loaded_private_wrapping_key = loaded_public_wrapping_key = None
        if private_encoded_key is not None:
            loaded_private_wrapping_key = serialization.load_der_private_key(
                data=private_encoded_key, password=password, backend=default_backend()
            )
        if public_encoded_key is not None:
            loaded_public_wrapping_key = serialization.load_der_public_key(
                data=public_encoded_key, backend=default_backend()
            )

        return cls(
            key_namespace=key_namespace,
            key_name=key_name,
            wrapping_algorithm=wrapping_algorithm,
            private_wrapping_key=loaded_private_wrapping_key,
            public_wrapping_key=loaded_public_wrapping_key,
        )

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key using generator keyring
        and encrypt it using any available wrapping key in any child keyring.

        :param EncryptionMaterials encryption_materials: Encryption materials for keyring to modify.
        :returns: Encryption materials containing data key and encrypted data key
        :rtype: EncryptionMaterials
        """
        new_materials = encryption_materials

        if self._public_wrapping_key is None:
            raise EncryptKeyError("A public key is required to encrypt")

        if new_materials.data_encryption_key is None:
            new_materials = _generate_data_key(encryption_materials=new_materials, key_provider=self._key_provider)

        try:
            # Encrypt data key
            encrypted_wrapped_key = EncryptedData(
                iv=None,
                ciphertext=self._public_wrapping_key.encrypt(
                    plaintext=new_materials.data_encryption_key.data_key, padding=self._wrapping_algorithm.padding,
                ),
                tag=None,
            )

            # EncryptedData to EncryptedDataKey
            encrypted_data_key = serialize_wrapped_key(
                key_provider=self._key_provider,
                wrapping_algorithm=self._wrapping_algorithm,
                wrapping_key_id=self.key_name,
                encrypted_wrapped_key=encrypted_wrapped_key,
            )
        except Exception:  # pylint: disable=broad-except
            error_message = "Raw RSA keyring unable to encrypt data key"
            _LOGGER.exception(error_message)
            raise EncryptKeyError(error_message)


        # Add encrypted data key to encryption_materials
        return new_materials.with_encrypted_data_key(encrypted_data_key=encrypted_data_key)

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param DecryptionMaterials decryption_materials: Decryption materials for keyring to modify.
        :param encrypted_data_keys: List of encrypted data keys.
        :type: List[EncryptedDataKey]
        :returns: Decryption materials that MAY include a plaintext data key
        :rtype: DecryptionMaterials
        """
        new_materials = decryption_materials

        if new_materials.data_encryption_key is not None:
            return new_materials

        if self._private_wrapping_key is None:
            return new_materials

        # Decrypt data key
        for key in encrypted_data_keys:
            if key.key_provider != self._key_provider:
                continue

            # Wrapped EncryptedDataKey to deserialized EncryptedData
            encrypted_wrapped_key = deserialize_wrapped_key(
                wrapping_algorithm=self._wrapping_algorithm, wrapping_key_id=self.key_name, wrapped_encrypted_key=key
            )
            try:
                plaintext_data_key = self._private_wrapping_key.decrypt(
                    ciphertext=encrypted_wrapped_key.ciphertext, padding=self._wrapping_algorithm.padding
                )
            except Exception:  # pylint: disable=broad-except
                error_message = "Raw RSA Keyring unable to decrypt data key"
                _LOGGER.exception(error_message)
                # The Raw RSA keyring MUST evaluate every encrypted data key
                # until it either succeeds or runs out of encrypted data keys.
                continue

            # Update decryption materials
            data_encryption_key = RawDataKey(key_provider=self._key_provider, data_key=plaintext_data_key)

            return new_materials.with_data_encryption_key(data_encryption_key=data_encryption_key)

        return new_materials
