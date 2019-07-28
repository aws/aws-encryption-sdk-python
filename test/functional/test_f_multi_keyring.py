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
"""Functional tests for Multi keyring encryption decryption path."""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.keyring.multi_keyring import MultiKeyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY_AES = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"

_SIGNING_KEY = b"aws-crypto-public-key"

_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
)

_ENCRYPTION_MATERIALS_WITH_DATA_KEY = EncryptionMaterials(
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
)

_MULTI_KEYRING_WITH_GENERATOR_AND_CHILDREN = MultiKeyring(
    generator=RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY_AES,
    ),
    children=[
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            private_wrapping_key=rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            ),
        ),
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            private_wrapping_key=rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            ),
        ),
    ],
)

_MULTI_KEYRING_WITHOUT_CHILDREN = MultiKeyring(
    generator=RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        private_wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
    )
)

_MULTI_KEYRING_WITHOUT_GENERATOR = MultiKeyring(
    children=[
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            private_wrapping_key=rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            ),
        ),
        RawAESKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=_WRAPPING_KEY_AES,
        ),
    ]
)


@pytest.mark.parametrize(
    "multi_keyring, encryption_materials",
    [
        (_MULTI_KEYRING_WITH_GENERATOR_AND_CHILDREN, _ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY),
        (_MULTI_KEYRING_WITH_GENERATOR_AND_CHILDREN, _ENCRYPTION_MATERIALS_WITH_DATA_KEY),
        (_MULTI_KEYRING_WITHOUT_CHILDREN, _ENCRYPTION_MATERIALS_WITH_DATA_KEY),
        (_MULTI_KEYRING_WITHOUT_GENERATOR, _ENCRYPTION_MATERIALS_WITH_DATA_KEY),
    ],
)
def test_multi_keyring_encryption_decryption(multi_keyring, encryption_materials):
    # Call on_encrypt function for the keyring
    encryption_materials = multi_keyring.on_encrypt(encryption_materials)

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        verification_key=b"ex_verification_key",
        encryption_context=_ENCRYPTION_CONTEXT,
    )

    # Call on_decrypt function for the keyring
    decryption_materials = multi_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    # Check if the data keys match
    assert encryption_materials.data_encryption_key == decryption_materials.data_encryption_key
