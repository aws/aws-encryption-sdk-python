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

import attr

import aws_encryption_sdk.internal.formatting.deserialize
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.structures import DataKey, RawDataKey


class RawAESKeyring(Keyring):
    """Public class for Raw AES Keyring."""

    def on_encrypt(self, encryption_materials):
        # Generate data key
        plaintext_data_key = os.urandom(encryption_materials.algorithm.kdf_input_len)

        # Encrypt data key
        wrapping_key = attr.ib(hash=True, validator=attr.validators.instance_of(WrappingKey))
        encrypted_wrapped_key = wrapping_key.encrypt(
            plaintext_data_key=plaintext_data_key, encryption_context=encryption_materials.encryption_context
        )
        encrypted_data_key = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            # WHAAAAT
            key_provider=self.key_provider,
            wrapping_algorithm=wrapping_key.wrapping_algorithm,
            # WHAAAAT
            wrapping_key_id=self.key_id,
            encrypted_wrapped_key=encrypted_wrapped_key,
        )

        # Update keyring trace

        # Update encryption materials
        encryption_materials.data_encryption_key = RawDataKey(
            # WHAAAAT
            key_provider=self.key_provider,
            data_key=plaintext_data_key,
        )
        encryption_materials.encrypted_data_keys.add(encrypted_data_key)

        return encryption_materials

    def on_decrypt(self, decryption_materials):
        # Decrypt data key

        # Update keyring trace

        return decryption_materials


class RawRSAKeyring(Keyring):
    """Public class for Raw RSA Keyring."""

    def on_encrypt(self, encryption_materials):
        return encryption_materials

    def on_decrypt(self, decryption_materials):
        return decryption_materials
