# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Functional tests for Raw AES keyring encryption decryption path."""

import pytest

from aws_encryption_sdk.identifiers import Algorithm, WrappingAlgorithm
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"key_a": "value_a", "key_b": "value_b", "key_c": "value_c"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"12345678901234567890123456789012"
_SIGNING_KEY = b"aws-crypto-public-key"

_ENCRYPTION_MATERIALS = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
)


def sample_aes_encryption_decryption():

    # Initializing attributes
    key_namespace = _PROVIDER_ID
    key_name = _KEY_ID
    _wrapping_algorithm = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING

    # Creating an instance of a raw AES keyring
    sample_raw_aes_keyring = RawAESKeyring(
        key_namespace=key_namespace,
        key_name=key_name,
        wrapping_key=_WRAPPING_KEY,
        wrapping_algorithm=_wrapping_algorithm,
    )

    # Call on_encrypt function for the keyring
    encryption_materials = sample_raw_aes_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS)

    print("PLAINTEXT DATA KEY")
    print(encryption_materials.data_encryption_key.data_key)

    print("ENCRYPTED DATA KEY")
    print(encryption_materials.encrypted_data_keys[0].encrypted_data_key)

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, verification_key=b"ex_verification_key",
        encryption_context=_ENCRYPTION_CONTEXT
    )

    # Call on_decrypt function for the keyring
    decryption_materials = sample_raw_aes_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys,
    )

    print("DECRYPTED DATA KEY")
    print(decryption_materials.data_encryption_key.data_key)

    # Check if the data keys match
    assert encryption_materials.data_encryption_key == decryption_materials.data_encryption_key


sample_aes_encryption_decryption()
