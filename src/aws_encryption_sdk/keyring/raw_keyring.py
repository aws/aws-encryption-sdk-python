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
"""Resources required for Raw Keyrings."""

import os
import logging

import attr
import six

from aws_encryption_sdk.internal.formatting.deserialize import deserialize_wrapped_key
from aws_encryption_sdk.internal.formatting.serialize import serialize_wrapped_key, serialize_raw_master_key_prefix
from aws_encryption_sdk.exceptions import EncryptKeyError
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.structures import MasterKeyInfo, RawDataKey, KeyringTrace
from aws_encryption_sdk.key_providers.raw import RawMasterKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def get_key_info_prefix(key_namespace, key_name, wrapping_key):
    # type: (str, bytes, WrappingKey) -> six.binary_type
    """Helper function to get key info prefix

    :param str key_namespace: String defining the keyring.
    :param bytes key_name: Key ID
    :param wrapping_key: Encryption key with which to wrap plaintext data key.
    :type wrapping_key: WrappingKey
    :return: Serialized key_info prefix
    :rtype: bytes
    """
    key_info_prefix = serialize_raw_master_key_prefix(RawMasterKey(provider_id=key_namespace,
                                                                   key_id=key_name,
                                                                   wrapping_key=wrapping_key
                                                                   )
                                                      )
    return key_info_prefix


def on_encrypt_helper(encryption_materials,  # type: EncryptionMaterials
                      key_provider,  # type: MasterKeyInfo
                      wrapping_key,  # type: WrappingKey
                      wrapping_algorithm,  # type: WrappingAlgorithm
                      key_name  # type: bytes
                      ):
    # type: (...) -> EncryptionMaterials
    """Helper function for the on_encrypt function of keyring.

    :param encryption_materials: Encryption materials for the keyring to modify.
    :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
    :param key_provider: Information about the key in the keyring.
    :type key_provider: MasterKeyInfo
    :param wrapping_key: Encryption key with which to wrap plaintext data key.
    :type wrapping_key: WrappingKey
    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key.
    :type wrapping_algorithm: WrappingAlgorithm
    :param bytes key_name: Key ID.
    :return: Optionally modified encryption materials.
    :rtype encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
    """
    # Create a keyring trace
    keyring_trace = KeyringTrace(
        wrapping_key=key_provider,
        flags=set()
    )

    # Check if data key already exists
    if not encryption_materials.data_encryption_key:

        # Generate data key
        plaintext_data_key = os.urandom(encryption_materials.algorithm.kdf_input_len)

        # Check if data key is generated
        if not plaintext_data_key:
            return EncryptKeyError("Unable to generate data encryption key.")

        # plaintext_data_key to RawDataKey
        data_encryption_key = RawDataKey(key_provider=key_provider, data_key=plaintext_data_key)

        # Add generated data key to encryption_materials
        encryption_materials.add_data_encryption_key(data_encryption_key, keyring_trace)

    else:
        plaintext_data_key = encryption_materials.data_encryption_key

    # Encrypt data key
    encrypted_wrapped_key = wrapping_key.encrypt(
        plaintext_data_key=plaintext_data_key, encryption_context=encryption_materials.encryption_context
    )

    # EncryptedData to EncryptedDataKey
    encrypted_data_key = serialize_wrapped_key(
        key_provider=key_provider,
        wrapping_algorithm=wrapping_algorithm,
        wrapping_key_id=key_name,
        encrypted_wrapped_key=encrypted_wrapped_key,
    )

    # Add encrypted data key to encryption_materials
    encryption_materials.add_encrypted_data_key(encrypted_data_key, keyring_trace)

    return encryption_materials


def on_decrypt_helper(decryption_materials,  # type: DecryptionMaterials
                      key_provider,  # type: MasterKeyInfo
                      wrapping_key,  # type: WrappingKey
                      wrapping_algorithm,  # type: WrappingAlgorithm
                      key_name,  # type: bytes
                      encrypted_data_key  # type: EncryptedDataKey
                      ):
    # type: (...) -> DecryptionMaterials
    """Helper function for the on_decrypt function of keyring.

    :param decryption_materials: Decryption materials for the keyring to modify.
    :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
    :param key_provider: Information about the key in the keyring.
    :type key_provider: MasterKeyInfo
    :param wrapping_key: Encryption key with which to wrap plaintext data key.
    :type wrapping_key: WrappingKey
    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key.
    :type wrapping_algorithm: WrappingAlgorithm
    :param bytes key_name: Key ID.
    :param encrypted_data_key: Data key encrypted with a wrapping key.
    :type encrypted_data_key: aws_encryption_sdk.structures.EncryptedDataKey
    :return: Optionally modified decryption materials.
    :rtype decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
    """
    # Create a keyring trace
    keyring_trace = KeyringTrace(
        wrapping_key=key_provider,
        flags=set()
    )

    # Check if plaintext data key exists
    if decryption_materials.data_key:
        return decryption_materials

    # Wrapped EncryptedDataKey to deserialized EncryptedData
    encrypted_wrapped_key = deserialize_wrapped_key(
        wrapping_algorithm=wrapping_algorithm, wrapping_key_id=key_name, wrapped_encrypted_key=encrypted_data_key
    )

    # EncryptedData to raw key string
    try:
        plaintext_data_key = wrapping_key.decrypt(
            encrypted_wrapped_data_key=encrypted_wrapped_key, encryption_context=decryption_materials.encryption_context
        )
    except Exception as error:
        logging.ERROR(error.__class__.__name__, ':', str(error))
        return decryption_materials

    # Update decryption materials
    data_encryption_key = RawDataKey(
        key_provider=MasterKeyInfo(provider_id=key_provider.provider_id,
                                   key_info=key_name),
        data_key=plaintext_data_key
    )
    decryption_materials.add_data_encryption_key(data_encryption_key, keyring_trace)

    return decryption_materials


@attr.s
class RawAESKeyring(Keyring):
    """Public class for Raw AES Keyring.

    :param str key_namespace: String defining the keyring.
    :param bytes key_name: Key ID
    :param wrapping_key: Encryption key with which to wrap plaintext data key.
    :type wrapping_key: WrappingKey
    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key.
    :type wrapping_algorithm: WrappingAlgorithm
    """

    key_namespace = attr.ib(validator=attr.validators.instance_of(six.string_types))
    key_name = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    _wrapping_key = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingKey))
    _wrapping_algorithm = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingAlgorithm))

    def __attrs_post_init__(self):
        # type: () -> None
        """Prepares initial values not handled by attrs."""
        self._key_provider = MasterKeyInfo(provider_id=self.key_namespace, key_info=self.key_name)

        self._key_info_prefix = get_key_info_prefix(key_namespace=self.key_namespace,
                                                    key_name=self.key_name,
                                                    wrapping_key=WrappingKey(
                                                        wrapping_algorithm=self._wrapping_algorithm,
                                                        wrapping_key=self._wrapping_key,
                                                        wrapping_key_type=EncryptionKeyType.SYMMETRIC
                                                    )
                                                    )

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param encryption_materials: Encryption materials for the keyring to modify.
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Optionally modified encryption materials.
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """
        encryption_materials = on_encrypt_helper(
            encryption_materials=encryption_materials, key_provider=self._key_provider,
            wrapping_key=self._wrapping_key, wrapping_algorithm=self._wrapping_algorithm,
            key_name=self.key_name
        )

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: Decryption materials for the keyring to modify.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :param encrypted_data_keys: List of encrypted data keys.
        :type: List of `aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Optionally modified decryption materials.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        # Decrypt data key
        expected_key_info_len = len(self._key_info_prefix) + self._wrapping_algorithm.algorithm.iv_len
        for key in encrypted_data_keys:
            if (key.key_provider.provider_id == self._key_provider.provider_id
                and len(key.key_provider.key_info) == expected_key_info_len
                and key.key_provider.key_info.startswith(self._key_info_prefix)
            ):
                decryption_materials = on_decrypt_helper(
                    decryption_materials=decryption_materials, key_provider=self._key_provider,
                    wrapping_key=self._wrapping_key, wrapping_algorithm=self._wrapping_algorithm,
                    key_name=self.key_name, encrypted_data_key=key
                )
                if decryption_materials.data_key:
                    return decryption_materials

        return decryption_materials


class RawRSAKeyring(Keyring):
    """Public class for Raw RSA Keyring.

    :param str key_namespace: String defining the keyring ID
    :param bytes key_name: Key ID
    :param wrapping_key: Encryption key with which to wrap plaintext data key
    :type wrapping_key: WrappingKey
    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key
    :type wrapping_algorithm: WrappingAlgorithm
    :param key_provider: Complete information about the key in the keyring
    :type key_provider: MasterKeyInfo
    """

    key_namespace = attr.ib(validator=attr.validators.instance_of(six.string_types))
    key_name = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    _wrapping_key = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingKey))
    _wrapping_algorithm = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingAlgorithm))

    def __attrs_post_init__(self):
        # type: () -> None
        """Prepares initial values not handled by attrs."""
        self._key_provider = MasterKeyInfo(provider_id=self.key_namespace, key_info=self.key_name)

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param encryption_materials: Encryption materials for the keyring to modify.
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Optionally modified encryption materials.
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """
        encryption_materials = on_encrypt_helper(
            encryption_materials=encryption_materials, key_provider=self._key_provider,
            wrapping_key=self._wrapping_key, wrapping_algorithm=self._wrapping_algorithm,
            key_name=self.key_name
        )

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: Decryption materials for the keyring to modify.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :param encrypted_data_keys: List of encrypted data keys.
        :type: List of `aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Optionally modified decryption materials.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        # Decrypt data key
        for key in encrypted_data_keys:
            if key.key_provider == self._key_provider:
                decryption_materials = on_decrypt_helper(
                    decryption_materials=decryption_materials, key_provider=self._key_provider,
                    wrapping_key=self._wrapping_key, wrapping_algorithm=self._wrapping_algorithm,
                    key_name=self.key_name, encrypted_data_key=key
                )

        return decryption_materials
