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

from aws_encryption_sdk.exceptions import EncryptKeyError
from aws_encryption_sdk.identifiers import (
    Algorithm,
    EncryptionKeyType,
    EncryptionType,
    KeyringTraceFlag,
    WrappingAlgorithm,
)
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = "5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_ALGORITHM = WrappingAlgorithm.RSA_OAEP_SHA256_MGF1

_PUBLIC_EXPONENT = 65537
_KEY_SIZE = 2048
_BACKEND = default_backend()

_PRIVATE_WRAPPING_KEY = rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)
_PUBLIC_WRAPPING_KEY = _PRIVATE_WRAPPING_KEY.public_key()

_PRIVATE_WRAPPING_KEY_PEM = _PRIVATE_WRAPPING_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_PUBLIC_WRAPPING_KEY_PEM = _PUBLIC_WRAPPING_KEY.public_bytes(
    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
)

_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITHOUT_PASSWORD = _PRIVATE_WRAPPING_KEY_PEM

_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITH_PASSWORD = _PRIVATE_WRAPPING_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"mypassword"),
)

_RAW_RSA_PUBLIC_KEY_PEM_ENCODED = _PUBLIC_WRAPPING_KEY_PEM

_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITHOUT_PASSWORD = _PRIVATE_WRAPPING_KEY.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITH_PASSWORD = _PRIVATE_WRAPPING_KEY.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"mypassword"),
)

_RAW_RSA_PUBLIC_KEY_DER_ENCODED = _PUBLIC_WRAPPING_KEY.public_bytes(
    encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def sample_encryption_materials():
    return [
        EncryptionMaterials(
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
        ),
        EncryptionMaterials(
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            data_encryption_key=RawDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
            ),
            encryption_context=_ENCRYPTION_CONTEXT,
            keyring_trace=[
                KeyringTrace(
                    wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                    flags={KeyringTraceFlag.GENERATED_DATA_KEY},
                )
            ],
        ),
    ]


def sample_raw_rsa_keyring_using_different_wrapping_algorithm():
    for alg in WrappingAlgorithm:
        if alg.encryption_type is EncryptionType.ASYMMETRIC:
            yield RawRSAKeyring(
                key_namespace=_PROVIDER_ID,
                key_name=_KEY_ID,
                wrapping_algorithm=alg,
                private_wrapping_key=_PRIVATE_WRAPPING_KEY,
                public_wrapping_key=_PUBLIC_WRAPPING_KEY,
            )
    pem_and_der_encoded_raw_rsa_keyring = [
        RawRSAKeyring.from_pem_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITHOUT_PASSWORD,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_PEM_ENCODED,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_pem_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITH_PASSWORD,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_PEM_ENCODED,
            password=b"mypassword",
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_pem_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_PEM_ENCODED,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_der_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITHOUT_PASSWORD,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_DER_ENCODED,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_der_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITH_PASSWORD,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_DER_ENCODED,
            password=b"mypassword",
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_der_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_DER_ENCODED,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
    ]
    for keyring in pem_and_der_encoded_raw_rsa_keyring:
        yield keyring


@pytest.mark.parametrize("encryption_materials_samples", sample_encryption_materials())
@pytest.mark.parametrize("test_raw_rsa_keyring", sample_raw_rsa_keyring_using_different_wrapping_algorithm())
def test_raw_rsa_encryption_decryption(encryption_materials_samples, test_raw_rsa_keyring):

    # Call on_encrypt function for the keyring
    encryption_materials = test_raw_rsa_keyring.on_encrypt(encryption_materials=encryption_materials_samples)

    assert encryption_materials.encrypted_data_keys is not None

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        verification_key=b"ex_verification_key",
        encryption_context=_ENCRYPTION_CONTEXT,
    )

    # Call on_decrypt function for the keyring
    decryption_materials = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    if test_raw_rsa_keyring._private_wrapping_key is not None:
        # Check if the data keys match
        assert encryption_materials.data_encryption_key.data_key == decryption_materials.data_encryption_key.data_key


@pytest.mark.parametrize("encryption_materials_samples", sample_encryption_materials())
def test_raw_master_key_decrypts_what_raw_keyring_encrypts(encryption_materials_samples):
    test_raw_rsa_keyring = RawRSAKeyring.from_pem_encoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        private_encoded_key=_PRIVATE_WRAPPING_KEY_PEM,
        public_encoded_key=_PUBLIC_WRAPPING_KEY_PEM,
    )

    # Creating an instance of a raw master key
    test_raw_master_key = RawMasterKey(
        key_id=_KEY_ID,
        provider_id=_PROVIDER_ID,
        wrapping_key=WrappingKey(
            wrapping_algorithm=_WRAPPING_ALGORITHM,
            wrapping_key=_PRIVATE_WRAPPING_KEY_PEM,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
        ),
    )

    # Call on_encrypt function for the keyring
    encryption_materials = test_raw_rsa_keyring.on_encrypt(encryption_materials=encryption_materials_samples)

    # Check if plaintext data key encrypted by raw keyring is decrypted by raw master key
    raw_mkp_decrypted_data_key = test_raw_master_key.decrypt_data_key_from_list(
        encrypted_data_keys=encryption_materials._encrypted_data_keys,
        algorithm=encryption_materials.algorithm,
        encryption_context=encryption_materials.encryption_context,
    ).data_key

    assert encryption_materials.data_encryption_key.data_key == raw_mkp_decrypted_data_key


@pytest.mark.parametrize("encryption_materials_samples", sample_encryption_materials())
def test_raw_keyring_decrypts_what_raw_master_key_encrypts(encryption_materials_samples):

    # Create instance of raw master key
    test_raw_master_key = RawMasterKey(
        key_id=_KEY_ID,
        provider_id=_PROVIDER_ID,
        wrapping_key=WrappingKey(
            wrapping_algorithm=_WRAPPING_ALGORITHM,
            wrapping_key=_PRIVATE_WRAPPING_KEY_PEM,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
        ),
    )

    test_raw_rsa_keyring = RawRSAKeyring.from_pem_encoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        private_encoded_key=_PRIVATE_WRAPPING_KEY_PEM,
        public_encoded_key=_PUBLIC_WRAPPING_KEY_PEM,
    )

    raw_mkp_generated_data_key = test_raw_master_key.generate_data_key(
        algorithm=encryption_materials_samples.algorithm,
        encryption_context=encryption_materials_samples.encryption_context,
    )

    raw_mkp_encrypted_data_key = test_raw_master_key.encrypt_data_key(
        data_key=raw_mkp_generated_data_key,
        algorithm=encryption_materials_samples.algorithm,
        encryption_context=encryption_materials_samples.encryption_context,
    )

    decryption_materials = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=DecryptionMaterials(
            algorithm=encryption_materials_samples.algorithm,
            encryption_context=encryption_materials_samples.encryption_context,
            verification_key=b"ex_verification_key",
        ),
        encrypted_data_keys=[raw_mkp_encrypted_data_key],
    )

    assert raw_mkp_generated_data_key.data_key == decryption_materials.data_encryption_key.data_key


def test_public_key_only_can_encrypt():
    test_keyring = RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        public_wrapping_key=_PUBLIC_WRAPPING_KEY,
    )
    initial_materials = EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
    )

    test_materials = test_keyring.on_encrypt(initial_materials)

    assert test_materials is not initial_materials
    assert test_materials.data_encryption_key is not None
    assert test_materials.encrypted_data_keys


def test_public_key_only_cannot_decrypt():
    test_keyring = RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        public_wrapping_key=_PUBLIC_WRAPPING_KEY,
    )
    initial_materials = EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
    )

    encryption_materials = test_keyring.on_encrypt(initial_materials)

    initial_decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
    )

    test_materials = test_keyring.on_decrypt(
        decryption_materials=initial_decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    assert test_materials is initial_decryption_materials


def test_private_key_can_decrypt():
    complete_keyring = RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        private_wrapping_key=_PRIVATE_WRAPPING_KEY,
        public_wrapping_key=_PUBLIC_WRAPPING_KEY,
    )
    test_keyring = RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        private_wrapping_key=_PRIVATE_WRAPPING_KEY,
    )
    initial_materials = EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
    )

    encryption_materials = complete_keyring.on_encrypt(initial_materials)

    initial_decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
    )

    test_materials = test_keyring.on_decrypt(
        decryption_materials=initial_decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    assert test_materials is not initial_decryption_materials
    assert test_materials.data_encryption_key is not None


def test_private_key_cannot_encrypt():
    test_keyring = RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=_WRAPPING_ALGORITHM,
        private_wrapping_key=_PRIVATE_WRAPPING_KEY,
    )
    initial_materials = EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context=_ENCRYPTION_CONTEXT
    )

    with pytest.raises(EncryptKeyError) as excinfo:
        test_keyring.on_encrypt(initial_materials)

    excinfo.match("A public key is required to encrypt")


def test_keypair_must_match():
    wrapping_key_a = rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)
    wrapping_key_b = rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)

    with pytest.raises(ValueError) as excinfo:
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
            private_wrapping_key=wrapping_key_a,
            public_wrapping_key=wrapping_key_b.public_key(),
        )

    excinfo.match("Private and public wrapping keys MUST be from the same keypair.")


def test_must_not_accept_aws_kms():
    bad_key_namespace = "aws-kms"

    with pytest.raises(ValueError) as excinfo:
        RawRSAKeyring(
            key_namespace=bad_key_namespace,
            key_name=_KEY_ID,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
            private_wrapping_key=_PRIVATE_WRAPPING_KEY,
            public_wrapping_key=_PUBLIC_WRAPPING_KEY,
        )

    excinfo.match('Key namespace MUST NOT be "aws-kms"')
