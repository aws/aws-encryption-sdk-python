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
from cryptography.hazmat.primitives.asymmetric import rsa
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.key_providers.raw
import aws_encryption_sdk.keyrings.raw
from aws_encryption_sdk.identifiers import KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring

from ....test_values import VALUES
from ....unit_test_utils import (
    _BACKEND,
    _DATA_KEY,
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

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def raw_rsa_keyring():
    return RawRSAKeyring.from_pem_encoding(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        private_encoded_key=VALUES["private_rsa_key_bytes"][1],
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


def test_keyring_trace_on_encrypt_when_data_encryption_key_given(raw_rsa_keyring):
    test_raw_rsa_keyring = raw_rsa_keyring

    test = test_raw_rsa_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_encryption_key())

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            # Check keyring trace does not contain KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
            assert KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY not in keyring_trace.flags


def test_on_encrypt_when_data_encryption_key_not_given(raw_rsa_keyring):
    test_raw_rsa_keyring = raw_rsa_keyring

    original_number_of_encrypted_data_keys = len(
        get_encryption_materials_without_data_encryption_key().encrypted_data_keys
    )

    test = test_raw_rsa_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_encryption_key())

    # Check if data key is generated
    assert test.data_encryption_key is not None

    generated_flag_count = 0
    encrypted_flag_count = 0

    for keyring_trace in test.keyring_trace:
        if (
            keyring_trace.wrapping_key.key_info == _KEY_ID
            and KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY in keyring_trace.flags
        ):
            # Check keyring trace contains KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
            generated_flag_count += 1
        if KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY in keyring_trace.flags:
            encrypted_flag_count += 1

    assert generated_flag_count == 1

    assert len(test.encrypted_data_keys) == original_number_of_encrypted_data_keys + 1

    assert encrypted_flag_count == 1


def test_on_decrypt_when_data_key_given(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    test_raw_rsa_keyring = raw_rsa_keyring
    test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_with_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],
    )
    assert not patch_decrypt_on_wrapping_key.called


def test_keyring_trace_on_decrypt_when_data_key_given(raw_rsa_keyring):
    test_raw_rsa_keyring = raw_rsa_keyring
    test = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_with_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],
    )
    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            # Check keyring trace does not contain KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags


def test_on_decrypt_when_data_key_and_edk_not_provided(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    test_raw_rsa_keyring = raw_rsa_keyring

    test = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(), encrypted_data_keys=[]
    )
    assert not patch_decrypt_on_wrapping_key.called

    for keyring_trace in test.keyring_trace:
        assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags

    assert test.data_encryption_key is None


def test_on_decrypt_when_data_key_not_provided_and_edk_not_in_keyring(raw_rsa_keyring, patch_decrypt_on_wrapping_key):
    test_raw_rsa_keyring = raw_rsa_keyring

    test = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_RSA],
    )
    assert not patch_decrypt_on_wrapping_key.called

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags

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


def test_keyring_trace_when_data_key_not_provided_and_edk_provided(raw_rsa_keyring):
    test_raw_rsa_keyring = raw_rsa_keyring

    test = test_raw_rsa_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=test_raw_rsa_keyring.on_encrypt(
            encryption_materials=get_encryption_materials_without_data_encryption_key()
        ).encrypted_data_keys,
    )
    decrypted_flag_count = 0

    for keyring_trace in test.keyring_trace:
        if KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY in keyring_trace.flags:
            decrypted_flag_count += 1

    assert decrypted_flag_count == 1
    assert test.data_encryption_key is not None
