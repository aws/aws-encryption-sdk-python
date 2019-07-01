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
import struct

import attr
import six

import aws_encryption_sdk.internal.formatting.deserialize
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.exceptions import EncryptKeyError
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.structures import DataKey, MasterKeyInfo, RawDataKey


def on_encrypt_helper(encryption_materials, key_provider, wrapping_key, wrapping_algorithm, key_name):
    """Helper function for the on_encrypt function of keyring.
    :param encryption_materials: Encryption materials for the keyring to modify.
    :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
    :param key_provider: Information abput the key in the keyring.
    :type key_provider: MasterKeyInfo
    :param wrapping_key: Encryption key with which to wrap plaintext data key.
    :type wrapping_key: WrappingKey
    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext data key.
    :type wrapping_algorithm: WrappingAlgorithm
    :param bytes key_name: Key ID.
    :return: Optionally modified encryption materials.
    :rtype encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
    """

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
        encryption_materials.add_data_encryption_key(data_encryption_key, encryption_materials.keyring_trace)

    else:
        plaintext_data_key = encryption_materials.data_encryption_key

    # Encrypt data key
    encrypted_wrapped_key = wrapping_key.encrypt(
        plaintext_data_key=plaintext_data_key, encryption_context=encryption_materials.encryption_context
    )

    # EncryptedData to EncryptedDataKey
    encrypted_data_key = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
        key_provider=key_provider,
        wrapping_algorithm=wrapping_algorithm,
        wrapping_key_id=key_name,
        encrypted_wrapped_key=encrypted_wrapped_key,
    )

    # Add encrypted data key to encryption_materials
    encryption_materials.add_encrypted_data_key(encrypted_data_key, encryption_materials.keyring_trace)

    return encryption_materials


def on_decrypt_helper(decryption_materials, wrapping_key, wrapping_algorithm, key_name, encrypted_data_key):
    """Helper function for the on_decrypt function of keyring.
    :param decryption_materials: Decryption materials for the keyring to modify.
    :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
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

    # Check if plaintext data key exists
    if decryption_materials.data_key:
        return decryption_materials

    # Wrapped EncryptedDataKey to deserialized EncryptedData
    encrypted_wrapped_key = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
        wrapping_algorithm=wrapping_algorithm, wrapping_key_id=key_name, wrapped_encrypted_key=encrypted_data_key
    )

    # EncryptedData to raw key string
    plaintext_data_key = wrapping_key.decrypt(
        encrypted_wrapped_data_key=encrypted_wrapped_key, encryption_context=decryption_materials.encryption_context
    )

    # Update decryption materials
    data_encryption_key = DataKey(
        key_provider=encrypted_data_key.key_provider,
        data_key=plaintext_data_key,
        encrypted_data_key=encrypted_data_key.encrypted_data_key,
    )
    decryption_materials.add_data_encryption_key(data_encryption_key, decryption_materials.keyring_trace)

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
    key_name = attr.ib(hash=True, validator=attr.validators.instance_of(six.binary_type))
    _wrapping_key = attr.ib(hash=True, repr=False, validator=attr.validators.instance_of(WrappingKey))
    _wrapping_algorithm = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingAlgorithm))

    def __attrs_post_init__(self):

        _key_provider = MasterKeyInfo(provider_id=self.key_namespace, key_info=self.key_name)

        _key_info_prefix = struct.pack(
            ">{}sII".format(len(self.key_name)),
            to_bytes(self.key_name),
            # Tag Length is stored in bits, not bytes
            self._wrapping_algorithm.algorithm.tag_len * 8,
            self._wrapping_algorithm.algorithm.iv_len,
        )

    def on_encrypt(self, encryption_materials):
        """Generate a data key if not present and encrypt it using any available wrapping key.
        :param encryption_materials: Encryption materials for the keyring to modify.
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Optionally modified encryption materials.
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

        encryption_materials = on_encrypt_helper(
            encryption_materials, self._key_provider, self._wrapping_key, self._wrapping_algorithm, self.key_name
        )

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
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
        if (
            encrypted_data_keys.key_provider.provider_id == self._key_provider.provider_id
            and len(encrypted_data_keys.key_provider.key_info) == expected_key_info_len
            and encrypted_data_keys.key_provider.key_info.startswith(self._key_info_prefix)
        ):
            decryption_materials = on_decrypt_helper(
                decryption_materials, self._wrapping_key, self._wrapping_algorithm, self.key_name, encrypted_data_keys
            )

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

    key_namespace = attr.ib(validator=attr.validators.instance_of(str))
    key_name = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    _wrapping_key = attr.ib(hash=True, repr=False, validator=attr.validators.instance_of(WrappingKey))
    _wrapping_algorithm = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingAlgorithm))

    _key_provider = MasterKeyInfo(provider_id=key_namespace, key_info=key_name)

    def on_encrypt(self, encryption_materials):
        """Generate a data key if not present and encrypt it using any available wrapping key.
        :param encryption_materials: Encryption materials for the keyring to modify.
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Optionally modified encryption materials.
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

        encryption_materials = on_encrypt_helper(
            encryption_materials, self._key_provider, self._wrapping_key, self._wrapping_algorithm, self.key_name
        )

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        """Attempt to decrypt the encrypted data keys.
        :param decryption_materials: Decryption materials for the keyring to modify.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :param encrypted_data_keys: List of encrypted data keys.
        :type: List of `aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Optionally modified decryption materials.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """

        # Decrypt data key
        if encrypted_data_keys.key_provider == self._key_provider:

            decryption_materials = on_decrypt_helper(
                decryption_materials, self._wrapping_key, self._wrapping_algorithm, self.key_name, encrypted_data_keys
            )

        return decryption_materials
