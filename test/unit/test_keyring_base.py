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
"""Unit tests for base keyring."""

import pytest

from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials


pytestmark = [pytest.mark.unit, pytest.mark.local]

_encryption_materials = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    encryption_context={"encryption": "context", "values": "here"},
    signing_key=b"aws-crypto-public-key",
)

_decryption_materials = DecryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, verification_key=b"ex_verification_key"
)

_encrypted_data_keys = []


def test_keyring_no_encrypt():
    with pytest.raises(NotImplementedError) as exc_info:
        Keyring().on_encrypt(encryption_materials=_encryption_materials)
    assert exc_info.match("Keyring does not implement on_encrypt function")


def test_keyring_no_decrypt():
    with pytest.raises(NotImplementedError) as exc_info:
        Keyring().on_decrypt(decryption_materials=_decryption_materials, encrypted_data_keys=_encrypted_data_keys)
    assert exc_info.match("Keyring does not implement on_decrypt function")
