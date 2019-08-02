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

from aws_encryption_sdk.identifiers import (
    Algorithm,
    EncryptionKeyType,
    EncryptionType,
    KeyringTraceFlag,
    WrappingAlgorithm,
)
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.keyring.raw_keyring import RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_ALGORITHM = WrappingAlgorithm.RSA_OAEP_SHA256_MGF1

_PUBLIC_EXPONENT = 65537
_KEY_SIZE = 2048
_BACKEND = default_backend()

_PRIVATE_WRAPPING_KEY = rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)

_PRIVATE_WRAPPING_KEY_PEM = (
    b"-----BEGIN RSA PRIVATE KEY-----\n"
    b"MIIEowIBAAKCAQEAo8uCyhiO4JUGZV+rtNq5DBA9Lm4xkw5kTA3v6EPybs8bVXL2\n"
    b"ZE6jkbo+xT4Jg/bKzUpnp1fE+T1ruGPtsPdoEmhY/P64LDNIs3sRq5U4QV9IETU1\n"
    b"vIcbNNkgGhRjV8J87YNY0tV0H7tuWuZRpqnS+gjV6V9lUMkbvjMCc5IBqQc3heut\n"
    b"/+fH4JwpGlGxOVXI8QAapnSy1XpCr3+PT29kydVJnIMuAoFrurojRpOQbOuVvhtA\n"
    b"gARhst1Ji4nfROGYkj6eZhvkz2Bkud4/+3lGvVU5LO1vD8oY7WoGtpin3h50VcWe\n"
    b"aBT4kejx4s9/G9C4R24lTH09J9HO2UUsuCqZYQIDAQABAoIBAQCfC90bCk+qaWqF\n"
    b"gymC+qOWwCn4bM28gswHQb1D5r6AtKBRD8mKywVvWs7azguFVV3Fi8sspkBA2FBC\n"
    b"At5p6ULoJOTL/TauzLl6djVJTCMM701WUDm2r+ZOIctXJ5bzP4n5Q4I7b0NMEL7u\n"
    b"ixib4elYGr5D1vrVQAKtZHCr8gmkqyx8Mz7wkJepzBP9EeVzETCHsmiQDd5WYlO1\n"
    b"C2IQYgw6MJzgM4entJ0V/GPytkodblGY95ORVK7ZhyNtda+r5BZ6/jeMW+hA3VoK\n"
    b"tHSWjHt06ueVCCieZIATmYzBNt+zEz5UA2l7ksg3eWfVORJQS7a6Ef4VvbJLM9Ca\n"
    b"m1kdsjelAoGBANKgvRf39i3bSuvm5VoyJuqinSb/23IH3Zo7XOZ5G164vh49E9Cq\n"
    b"dOXXVxox74ppj/kbGUoOk+AvaB48zzfzNvac0a7lRHExykPH2kVrI/NwH/1OcT/x\n"
    b"2e2DnFYocXcb4gbdZQ+m6X3zkxOYcONRzPVW1uMrFTWHcJveMUm4PGx7AoGBAMcU\n"
    b"IRvrT6ye5se0s27gHnPweV+3xjsNtXZcK82N7duXyHmNjxrwOAv0SOhUmTkRXArM\n"
    b"6aN5D8vyZBSWma2TgUKwpQYFTI+4Sp7sdkkyojGAEixJ+c5TZJNxZFrUe0FwAoic\n"
    b"c2kb7ntaiEj5G+qHvykJJro5hy6uLnjiMVbAiJDTAoGAKb67241EmHAXGEwp9sdr\n"
    b"2SMjnIAnQSF39UKAthkYqJxa6elXDQtLoeYdGE7/V+J2K3wIdhoPiuY6b4vD0iX9\n"
    b"JcGM+WntN7YTjX2FsC588JmvbWfnoDHR7HYiPR1E58N597xXdFOzgUgORVr4PMWQ\n"
    b"pqtwaZO3X2WZlvrhr+e46hMCgYBfdIdrm6jYXFjL6RkgUNZJQUTxYGzsY+ZemlNm\n"
    b"fGdQo7a8kePMRuKY2MkcnXPaqTg49YgRmjq4z8CtHokRcWjJUWnPOTs8rmEZUshk\n"
    b"0KJ0mbQdCFt/Uv0mtXgpFTkEZ3DPkDTGcV4oR4CRfOCl0/EU/A5VvL/U4i/mRo7h\n"
    b"ye+xgQKBgD58b+9z+PR5LAJm1tZHIwb4tnyczP28PzwknxFd2qylR4ZNgvAUqGtU\n"
    b"xvpUDpzMioz6zUH9YV43YNtt+5Xnzkqj+u9Mr27/H2v9XPwORGfwQ5XPwRJz/2oC\n"
    b"EnPmP1SZoY9lXKUpQXHXSpDZ2rE2Klt3RHMUMHt8Zpy36E8Vwx8o\n"
    b"-----END RSA PRIVATE KEY-----\n"
)

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
                    flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
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
            )
    pem_and_der_encoded_raw_rsa_keyring = [
        RawRSAKeyring.from_pem_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITHOUT_PASSWORD,
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_pem_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_PEM_ENCODED_WITH_PASSWORD,
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
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_der_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            private_encoded_key=_RAW_RSA_PRIVATE_KEY_DER_ENCODED_WITH_PASSWORD,
            password=b"mypassword",
            wrapping_algorithm=_WRAPPING_ALGORITHM,
        ),
        RawRSAKeyring.from_der_encoding(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            public_encoded_key=_RAW_RSA_PUBLIC_KEY_DER_ENCODED,
            password=b"mypassword",
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
