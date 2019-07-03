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

from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, WrappingKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_PLAINTEXT_DATA_KEY = [b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(', ]
_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_KEY_INFO = b"5325b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80\x00\x00\x00\x0c\xe0h\xe2NT\x1c\xb8\x8f!\t\xc2\x94"


@pytest.mark.parametrize("plaintext_data_key, wrapping_key, key_info")
def test_raw_aes_encryption_decryption(plaintext_data_key):

    key_namespace = _PROVIDER_ID
    key_name = _KEY_ID
    _wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                wrapping_key=_WRAPPING_KEY)

    encryption_materials = RawAESKeyring.on_encrypt(encryption_materials=encryption_materials)
    decryption_materials = RawAESKeyring.on_encrypt(decryption_materials=decryption_materials,
                                                    encrypted_data_keys=encryption_materials.encrypted_data_keys)
    assert encryption_materials.data_encryption_key == decryption_materials.data_key
