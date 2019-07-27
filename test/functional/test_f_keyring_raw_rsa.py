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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.keyring.raw_keyring import RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_SIGNING_KEY = b"aws-crypto-public-key"
_WRAPPING_ALGORITHM = WrappingAlgorithm.RSA_OAEP_SHA256_MGF1

_PUBLIC_EXPONENT = 65537
_KEY_SIZE = 2048
_BACKEND = default_backend()

_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITHOUT_PASSWORD = rsa.generate_private_key(
    public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
).private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITH_PASSWORD = rsa.generate_private_key(
    public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
).private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"mypassword"),
)

_RAW_RSA_PUBLIC_KEY_PEM_ENCODED = (
    rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)
    .public_key()
    .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
)

_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITHOUT_PASSWORD = rsa.generate_private_key(
    public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
).private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITH_PASSWORD = rsa.generate_private_key(
    public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
).private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"mypassword"),
)

_RAW_RSA_PUBLIC_KEY_DER_ENCODED = (
    rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)
    .public_key()
    .public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
)

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

_RAW_RSA_KEYRINGS = [
    RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        private_wrapping_key=rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
        ),
    ),
    RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
        private_wrapping_key=rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
        ),
    ),
    RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA384_MGF1,
        private_wrapping_key=rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
        ),
    ),
    RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
        private_wrapping_key=rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
        ),
    ),
    RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_PKCS1,
        private_wrapping_key=rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND
        ),
    ),
    RawRSAKeyring.fromPEMEncoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        private_encoded_key=_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITHOUT_PASSWORD,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
    RawRSAKeyring.fromPEMEncoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        private_encoded_key=_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITH_PASSWORD,
        password=b"mypassword",
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
    RawRSAKeyring.fromPEMEncoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        public_encoded_key=_RAW_RSA_PUBLIC_KEY_PEM_ENCODED,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
    RawRSAKeyring.fromDEREncoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        private_encoded_key=_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITHOUT_PASSWORD,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
    RawRSAKeyring.fromDEREncoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        private_encoded_key=_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITH_PASSWORD,
        password=b"mypassword",
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
    RawRSAKeyring.fromDEREncoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        public_encoded_key=_RAW_RSA_PUBLIC_KEY_DER_ENCODED,
        password=b"mypassword",
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
]


@pytest.mark.parametrize("encryption_materials_samples", _ENCRYPTION_MATERIALS)
@pytest.mark.parametrize("test_raw_rsa_keyring", _RAW_RSA_KEYRINGS)
def test_raw_rsa_encryption_decryption(encryption_materials_samples, test_raw_rsa_keyring):

    # Call on_encrypt function for the keyring
    encryption_materials = test_raw_rsa_keyring.on_encrypt(encryption_materials=encryption_materials_samples)

    assert encryption_materials.encrypted_data_keys is not None

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, verification_key=b"ex_verification_key"
    )

    # Call on_decrypt function for the keyring
    decryption_materials = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    if test_raw_rsa_keyring._private_wrapping_key is not None:
        # Check if the data keys match
        assert encryption_materials.data_encryption_key.data_key == decryption_materials.data_encryption_key.data_key
