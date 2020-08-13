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
"""Unit tests for Raw AES keyring."""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk.key_providers.raw
import aws_encryption_sdk.keyrings.raw
from aws_encryption_sdk.exceptions import EncryptKeyError
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring

from ...unit_test_utils import (
    _BACKEND,
    _DATA_KEY,
    _ENCRYPTED_DATA_KEY_AES,
    _ENCRYPTED_DATA_KEY_RSA,
    _ENCRYPTION_CONTEXT,
    _KEY_ID,
    _KEY_SIZE,
    _PROVIDER_ID,
    _PUBLIC_EXPONENT,
    get_decryption_materials_with_data_encryption_key,
    get_decryption_materials_without_data_encryption_key,
    get_encryption_materials_with_data_encryption_key,
    get_encryption_materials_without_data_encryption_key,
)
from ...vectors import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def raw_rsa_keyring():
    private_key = serialization.load_pem_private_key(
        data=VALUES["private_rsa_key_bytes"][1], password=None, backend=default_backend()
    )
    return RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        private_wrapping_key=private_key,
        public_wrapping_key=private_key.public_key(),
    )


def raw_rsa_private_key():
    return rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE, backend=_BACKEND)


@pytest.fixture
def patch_generate_data_key(mocker):
    mocker.patch.object(aws_encryption_sdk.keyrings.raw, "_generate_data_key")
    return aws_encryption_sdk.keyrings.raw._generate_data_key


@pytest.fixture
def patch_decrypt_on_wrapping_key(mocker):
    mocker.patch.object(WrappingKey, "decrypt")
    return WrappingKey.decrypt


@pytest.fixture
def patch_os_urandom(mocker):
    mocker.patch.object(aws_encryption_sdk.key_providers.raw.os, "urandom")
    return aws_encryption_sdk.key_providers.raw.os.urandom


def test_parent():
    assert issubclass(RawRSAKeyring, Keyring)


def test_valid_parameters(raw_rsa_keyring):
    test = raw_rsa_keyring
    assert test.key_namespace == _PROVIDER_ID
    assert test.key_name == _KEY_ID
    assert test._wrapping_algorithm == WrappingAlgorithm.RSA_OAEP_SHA256_MGF1
    assert isinstance(test._private_wrapping_key, rsa.RSAPrivateKey)


@pytest.mark.parametrize(
    "key_namespace, key_name, wrapping_algorithm, private_wrapping_key, public_wrapping_key",
    (
        (_PROVIDER_ID, None, WrappingAlgorithm.RSA_OAEP_SHA256_MGF1, raw_rsa_private_key(), None),
        (None, None, None, None, None),
        (_PROVIDER_ID, _KEY_ID, WrappingAlgorithm.RSA_OAEP_SHA256_MGF1, WrappingAlgorithm.RSA_OAEP_SHA256_MGF1, None),
        (None, None, None, raw_rsa_private_key(), raw_rsa_private_key().public_key()),
        (len(_PROVIDER_ID), len(_KEY_ID), _PROVIDER_ID, _PROVIDER_ID, _KEY_ID),
    ),
)
def test_invalid_parameters(key_namespace, key_name, wrapping_algorithm, private_wrapping_key, public_wrapping_key):
    with pytest.raises(TypeError):
        RawRSAKeyring(
            key_namespace=key_namespace,
            key_name=key_name,
            wrapping_algorithm=wrapping_algorithm,
            private_wrapping_key=private_wrapping_key,
            public_wrapping_key=public_wrapping_key,
        )


@pytest.mark.parametrize(
    "wrapping_algorithm",
    (
        WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
        WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
        WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    ),
)
def test_invalid_wrapping_algorithm_suite(wrapping_algorithm):
    with pytest.raises(ValueError):
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=wrapping_algorithm,
            private_wrapping_key=raw_rsa_private_key(),
        )


def test_public_and_private_key_not_provided():
    with pytest.raises(TypeError) as exc_info:
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID, key_name=_KEY_ID, wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1
        )
    assert exc_info.match("At least one of public key or private key must be provided.")


def test_on_encrypt_when_data_encryption_key_given(raw_rsa_keyring, patch_generate_data_key):
    test_raw_rsa_keyring = raw_rsa_keyring

    test_raw_rsa_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_encryption_key())
    # Check if keyring is generated
    assert not patch_generate_data_key.called


def test_on_encrypt_no_public_key(raw_rsa_keyring):
    private_key = raw_rsa_private_key()
    test_keyring = RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        private_wrapping_key=private_key,
    )

    initial_materials = get_encryption_materials_without_data_encryption_key()

    with pytest.raises(EncryptKeyError) as excinfo:
        test_keyring.on_encrypt(encryption_materials=initial_materials)

    excinfo.match("A public key is required to encrypt")


def test_on_encrypt_when_data_encryption_key_not_given(raw_rsa_keyring):
    test_raw_rsa_keyring = raw_rsa_keyring

    original_number_of_encrypted_data_keys = len(
        get_encryption_materials_without_data_encryption_key().encrypted_data_keys
    )

    test = test_raw_rsa_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_encryption_key())

    assert test.data_encryption_key.data_key is not None

    assert len(test.encrypted_data_keys) == original_number_of_encrypted_data_keys + 1


def test_on_decrypt_when_data_key_given(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    test_raw_rsa_keyring = raw_rsa_keyring
    test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_with_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],
    )
    assert not patch_decrypt_on_wrapping_key.called


def test_on_decrypt_no_private_key(raw_rsa_keyring):
    raw_rsa_keyring._private_wrapping_key = None

    materials = get_decryption_materials_without_data_encryption_key()
    test = raw_rsa_keyring.on_decrypt(decryption_materials=materials, encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],)

    assert test is materials


def test_on_decrypt_when_data_key_and_edk_not_provided(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    test_raw_rsa_keyring = raw_rsa_keyring

    test = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(), encrypted_data_keys=[]
    )
    assert not patch_decrypt_on_wrapping_key.called

    assert test.data_encryption_key is None


def test_on_decrypt_when_data_key_not_provided_and_no_know_edks(raw_rsa_keyring, mocker):
    patched_wrapping_key_decrypt = mocker.patch.object(raw_rsa_keyring._private_wrapping_key, "decrypt")

    test = raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES],
    )

    assert not patched_wrapping_key_decrypt.called

    assert test.data_encryption_key is None


def test_on_decrypt_when_data_key_not_provided_and_edk_not_in_keyring(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    test_raw_rsa_keyring = raw_rsa_keyring

    test = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],
    )
    assert not patch_decrypt_on_wrapping_key.called

    assert test.data_encryption_key is None


def test_on_decrypt_when_data_key_not_provided_and_edk_provided(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    patch_decrypt_on_wrapping_key.return_value = _DATA_KEY
    test_raw_rsa_keyring = raw_rsa_keyring

    test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],
    )
    assert patch_decrypt_on_wrapping_key.called_once_with(
        encrypted_wrapped_data_key=_ENCRYPTED_DATA_KEY_RSA, encryption_context=_ENCRYPTION_CONTEXT
    )


def test_on_decrypt_continues_through_edks_on_failure(raw_rsa_keyring, mocker):
    patched_wrapping_key_decrypt = mocker.patch.object(raw_rsa_keyring._private_wrapping_key, "decrypt")
    patched_wrapping_key_decrypt.side_effect = (Exception("DECRYPT FAIL"), _DATA_KEY)

    test = raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=(_ENCRYPTED_DATA_KEY_RSA, _ENCRYPTED_DATA_KEY_RSA),
    )

    assert patched_wrapping_key_decrypt.call_count == 2

    assert test.data_encryption_key.data_key == _DATA_KEY
