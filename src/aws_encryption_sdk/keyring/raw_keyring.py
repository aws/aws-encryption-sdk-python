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

import aws_encryption_sdk.internal.formatting.deserialize
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.structures import DataKey, MasterKeyInfo, RawDataKey


@attr.s
class RawAESKeyring(Keyring):
    """Public class for Raw AES Keyring."""

    key_namespace = attr.ib(validator=attr.validators.instance_of(str))
    key_name = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    wrapping_key = attr.ib(hash=True, validator=attr.validators.instance_of(WrappingKey))
    wrapping_algorithm = attr.ib(validator=attr.validators.instance_of(WrappingAlgorithm))

    key_provider = MasterKeyInfo(provider_id=key_namespace, key_info=key_name)

    key_info_prefix = struct.pack(
        ">{}sII".format(len(key_name)),
        to_bytes(key_name),
        # Tag Length is stored in bits, not bytes
        wrapping_algorithm.algorithm.tag_len * 8,
        wrapping_algorithm.algorithm.iv_len,
    )

    def on_encrypt(self, encryption_materials):
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param encryption_materials: Contains signing key, encryption context and algorithm suite
                                    required to encrypt data key
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Contains signing key, unencrypted data key, encrypted data keys,
                                    encryption context and algorithm suite required to encrypt data key
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

        # Generate data key
        plaintext_data_key = os.urandom(encryption_materials.algorithm.kdf_input_len)

        # Encrypt data key
        encrypted_wrapped_key = self.wrapping_key.encrypt(
            plaintext_data_key=plaintext_data_key, encryption_context=encryption_materials.encryption_context
        )

        encrypted_data_key = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.key_provider,
            wrapping_algorithm=self.wrapping_algorithm,
            wrapping_key_id=self.key_name,
            encrypted_wrapped_key=encrypted_wrapped_key,
        )

        # Update keyring trace

        # Update encryption materials
        encryption_materials.data_encryption_key = RawDataKey(
            key_provider=self.key_provider, data_key=plaintext_data_key
        )
        encryption_materials.encrypted_data_keys.add(encrypted_data_key)

        return encryption_materials

    def on_decrypt(self, decryption_materials):
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: Contains verification key, list of encrypted data keys.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :returns: Contains verification key, list of encrypted data keys and decrypted data key.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """

        # Decrypt data key
        expected_key_info_len = len(self.key_info_prefix) + self.wrapping_algorithm.algorithm.iv_len
        if (
            decryption_materials.encrypted_data_key.key_provider.provider_id == self.key_provider.provider_id
            and len(decryption_materials.encrypted_data_key.key_provider.key_info) == expected_key_info_len
            and decryption_materials.encrypted_data_key.key_provider.key_info.startswith(self.key_info_prefix)
        ):
            encrypted_wrapped_key = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.wrapping_algorithm,
                wrapping_key_id=self.key_name,
                wrapped_encrypted_key=decryption_materials.encrypted_data_key,
            )
            plaintext_data_key = self.wrapping_key.decrypt(
                encrypted_wrapped_data_key=encrypted_wrapped_key,
                encryption_context=decryption_materials.encryption_context,
            )
            decryption_materials.data_key = DataKey(
                key_provider=decryption_materials.encrypted_data_key.key_provider,
                data_key=plaintext_data_key,
                encrypted_data_key=decryption_materials.encrypted_data_key.encrypted_data_key,
            )

        # Update keyring trace

        return decryption_materials


class RawRSAKeyring(Keyring):
    """Public class for Raw RSA Keyring."""

    key_namespace = attr.ib(validator=attr.validators.instance_of(str))
    key_name = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    wrapping_key = attr.ib(hash=True, validator=attr.validators.instance_of(WrappingKey))
    wrapping_algorithm = attr.ib(validator=attr.validators.instance_of(WrappingAlgorithm))

    key_provider = MasterKeyInfo(provider_id=key_namespace, key_info=key_name)

    def on_encrypt(self, encryption_materials):
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param encryption_materials: Contains signing key, encryption context and algorithm suite
                                    required to encrypt data key
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Contains signing key, unencrypted data key, encrypted data keys,
                                    encryption context and algorithm suite required to encrypt data key
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

        # Generate data key
        plaintext_data_key = os.urandom(encryption_materials.algorithm.kdf_input_len)

        # Encrypt data key
        encrypted_wrapped_key = self.wrapping_key.encrypt(
            plaintext_data_key=plaintext_data_key, encryption_context=encryption_materials.encryption_context
        )

        encrypted_data_key = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.key_provider,
            wrapping_algorithm=self.wrapping_algorithm,
            wrapping_key_id=self.key_name,
            encrypted_wrapped_key=encrypted_wrapped_key,
        )

        # Update keyring trace

        # Update encryption materials
        encryption_materials.data_encryption_key = RawDataKey(
            key_provider=self.key_provider, data_key=plaintext_data_key
        )
        encryption_materials.encrypted_data_keys.add(encrypted_data_key)

        return encryption_materials

    def on_decrypt(self, decryption_materials):
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: Contains verification key, list of encrypted data keys.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :returns: Contains verification key, list of encrypted data keys and decrypted data key.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """

        # Decrypt data key
        if decryption_materials.encrypted_data_key.key_provider == self.key_provider:
            encrypted_wrapped_key = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.wrapping_algorithm,
                wrapping_key_id=self.key_name,
                wrapped_encrypted_key=decryption_materials.encrypted_data_key,
            )
            plaintext_data_key = self.wrapping_key.decrypt(
                encrypted_wrapped_data_key=encrypted_wrapped_key,
                encryption_context=decryption_materials.encryption_context,
            )
            decryption_materials.data_key = DataKey(
                key_provider=decryption_materials.encrypted_data_key.key_provider,
                data_key=plaintext_data_key,
                encrypted_data_key=decryption_materials.encrypted_data_key.encrypted_data_key,
            )

        # Update keyring trace
        return decryption_materials
