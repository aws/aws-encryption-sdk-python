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

from aws_encryption_sdk.identifiers import WrappingAlgorithm, Algorithm, EncryptionKeyType
from aws_encryption_sdk.structures import MasterKeyInfo, DataKey, EncryptedDataKey
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, RawRSAKeyring, WrappingKey
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.materials_managers.default import Signer

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_SIGNING_KEY = Signer.encoded_public_key()

_ENCRYPTION_MATERIALS = [
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY
    ),
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=DataKey(
            key_provider=MasterKeyInfo(
                provider_id=_PROVIDER_ID,
                key_info=_KEY_ID
            ),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e('
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    ),
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=DataKey(
            key_provider=MasterKeyInfo(
                provider_id=_PROVIDER_ID,
                key_info=_KEY_ID
            ),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e('
        ),
        encrypted_data_keys=[
            EncryptedDataKey(
                key_provider=_PROVIDER_ID,
                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                                   b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
            )
        ],
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    )
]


@pytest.mark.parametrize("encryption_materials",_ENCRYPTION_MATERIALS)
def test_raw_rsa_encryption_decryption(encryption_materials):

    # Initializing attributes
    key_namespace = _PROVIDER_ID
    key_name = _KEY_ID
    _wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                wrapping_key=_WRAPPING_KEY,
                                wrapping_key_type=EncryptionKeyType.SYMMETRIC)
    _wrapping_algorithm = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING

    # Creating an instance of a raw AES keyring
    fake_raw_rsa_keyring = RawRSAKeyring(key_namespace=key_namespace,
                                         key_name=key_name,
                                         wrapping_key=_wrapping_key,
                                         wrapping_algorithm=_wrapping_algorithm)

    # Call on_encrypt function for the keyring
    encryption_materials = fake_raw_rsa_keyring.on_encrypt(encryption_materials=encryption_materials)

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(verification_key=b"ex_verification_key")

    # Call on_decrypt function for the keyring
    decryption_materials = fake_raw_rsa_keyring.on_decrypt(decryption_materials=decryption_materials,
                                                           encrypted_data_keys=encryption_materials.encrypted_data_keys)

    # Check if the data keys match
    assert encryption_materials.data_encryption_key == decryption_materials.data_key
