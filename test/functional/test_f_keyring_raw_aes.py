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

from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"12345678901234567890123456789012"
_SIGNING_KEY = b"aws-crypto-public-key"

_WRAPPING_ALGORITHM = [
    WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
    WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
]

_ENCRYPTION_MATERIALS = [
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    ),
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
            )
        ],
    ),
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encrypted_data_keys=[
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
            )
        ],
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={
                    KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
                    KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY,
                },
            )
        ],
    ),
]
#
# _KEY_INFO_VECTORS = [
#     (b"5325b043-5843-4629-869c-64794af77ada", b"5325b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80\x00\x00\x00\x0c",
#      WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING),
#     (b"30456b043-0323-4452-332a", b"30456b043-0323-4452-332a\x00\x00\x00\x80\x00\x00\x00\x0c",
#      WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING)
# ]


@pytest.mark.parametrize("encryption_materials_samples", _ENCRYPTION_MATERIALS)
@pytest.mark.parametrize("wrapping_algorithm_samples", _WRAPPING_ALGORITHM)
def test_raw_aes_encryption_decryption(encryption_materials_samples, wrapping_algorithm_samples):

    # Initializing attributes
    key_namespace = _PROVIDER_ID
    key_name = _KEY_ID
    _wrapping_algorithm = wrapping_algorithm_samples

    # Creating an instance of a raw AES keyring
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=key_namespace,
        key_name=key_name,
        wrapping_key=_WRAPPING_KEY,
        wrapping_algorithm=_wrapping_algorithm,
    )

    # Call on_encrypt function for the keyring
    encryption_materials = test_raw_aes_keyring.on_encrypt(encryption_materials=encryption_materials_samples)

    print("PLAINTEXT DATA KEY")
    print(encryption_materials.data_encryption_key)

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        verification_key=b"ex_verification_key",
        encryption_context=_ENCRYPTION_CONTEXT,
    )

    # Call on_decrypt function for the keyring
    decryption_materials = test_raw_aes_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    # Check if the data keys match
    assert encryption_materials.data_encryption_key.data_key == decryption_materials.data_encryption_key.data_key

    test_raw_master_key = RawMasterKey(
        key_id=test_raw_aes_keyring.key_name,
        provider_id=test_raw_aes_keyring.key_namespace,
        wrapping_key=test_raw_aes_keyring._wrapping_key_structure,
    )
    encryption_materials = test_raw_aes_keyring.on_encrypt(encryption_materials=encryption_materials_samples)

    assert (
        encryption_materials.data_encryption_key.data_key
        == test_raw_master_key.decrypt_data_key_from_list(
            encrypted_data_keys=encryption_materials._encrypted_data_keys,
            algorithm=encryption_materials.algorithm,
            encryption_context=encryption_materials.encryption_context,
        ).data_key
    )

    if encryption_materials_samples.data_encryption_key is not None:
        raw_master_key_encrypted_data_key = test_raw_master_key.encrypt_data_key(
            data_key=encryption_materials_samples.data_encryption_key,
            algorithm=encryption_materials_samples.algorithm,
            encryption_context=encryption_materials_samples.encryption_context,
        )
        assert (
            encryption_materials_samples.data_encryption_key.data_key
            == test_raw_aes_keyring.on_decrypt(
                decryption_materials=DecryptionMaterials(
                    algorithm=encryption_materials_samples.algorithm,
                    encryption_context=encryption_materials_samples.encryption_context,
                    verification_key=b"ex_verification_key",
                ),
                encrypted_data_keys=[raw_master_key_encrypted_data_key],
            ).data_encryption_key.data_key
        )
