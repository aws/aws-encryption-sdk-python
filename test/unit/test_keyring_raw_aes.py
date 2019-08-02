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

import os

import mock
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.key_providers.raw
import aws_encryption_sdk.keyring.raw_keyring
from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.keyring.raw_keyring import GenerateKeyError, RawAESKeyring, _generate_data_key
from aws_encryption_sdk.materials_managers import EncryptionMaterials
from aws_encryption_sdk.structures import MasterKeyInfo

from .unit_test_utils import (
    _DATA_KEY,
    _ENCRYPTED_DATA_KEY_AES,
    _ENCRYPTED_DATA_KEY_NOT_IN_KEYRING,
    _ENCRYPTION_CONTEXT,
    _KEY_ID,
    _PROVIDER_ID,
    _SIGNING_KEY,
    _WRAPPING_KEY,
    get_decryption_materials_with_data_encryption_key,
    get_decryption_materials_without_data_encryption_key,
    get_encryption_materials_with_data_encryption_key,
    get_encryption_materials_without_data_encryption_key,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def raw_aes_keyring():
    return RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )


@pytest.fixture
def patch_generate_data_key(mocker):
    mocker.patch.object(aws_encryption_sdk.keyring.raw_keyring, "_generate_data_key")
    return aws_encryption_sdk.keyring.raw_keyring._generate_data_key


@pytest.fixture
def patch_decrypt_on_wrapping_key(mocker):
    mocker.patch.object(WrappingKey, "decrypt")
    return WrappingKey.decrypt


@pytest.fixture
def patch_os_urandom(mocker):
    mocker.patch.object(os, "urandom")
    return os.urandom


def test_parent():
    assert issubclass(RawAESKeyring, Keyring)


def test_valid_parameters(raw_aes_keyring):
    test = raw_aes_keyring
    assert test.key_name == _KEY_ID
    assert test.key_namespace == _PROVIDER_ID
    assert test._wrapping_algorithm == WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
    assert test._wrapping_key == _WRAPPING_KEY


@pytest.mark.parametrize(
    "key_namespace, key_name, wrapping_algorithm, wrapping_key",
    (
        (_PROVIDER_ID, None, WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING, None),
        (None, None, None, None),
        (
            _PROVIDER_ID,
            _KEY_ID,
            WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        ),
    ),
)
def test_invalid_parameters(key_namespace, key_name, wrapping_algorithm, wrapping_key):
    with pytest.raises(TypeError):
        RawAESKeyring(
            key_namespace=key_namespace,
            key_name=key_name,
            wrapping_algorithm=wrapping_algorithm,
            wrapping_key=wrapping_key,
        )


def test_on_encrypt_when_data_encryption_key_given(raw_aes_keyring, patch_generate_data_key):
    test_raw_aes_keyring = raw_aes_keyring

    test_raw_aes_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_encryption_key())
    # Check if keyring is generated
    assert not patch_generate_data_key.called


def test_keyring_trace_on_encrypt_when_data_encryption_key_given(raw_aes_keyring):
    test_raw_aes_keyring = raw_aes_keyring

    test = test_raw_aes_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_encryption_key())

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            # Check keyring trace does not contain KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
            assert KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY not in keyring_trace.flags


def test_on_encrypt_when_data_encryption_key_not_given(raw_aes_keyring):

    test_raw_aes_keyring = raw_aes_keyring

    original_number_of_encrypted_data_keys = len(
        get_encryption_materials_without_data_encryption_key().encrypted_data_keys
    )

    test = test_raw_aes_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_encryption_key())

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


@pytest.mark.parametrize(
    "decryption_materials, edk",
    (
        (get_decryption_materials_with_data_encryption_key(), [_ENCRYPTED_DATA_KEY_AES]),
        (get_decryption_materials_with_data_encryption_key(), []),
    ),
)
def test_on_decrypt_when_data_key_given(raw_aes_keyring, decryption_materials, edk, patch_decrypt_on_wrapping_key):
    test_raw_aes_keyring = raw_aes_keyring
    test_raw_aes_keyring.on_decrypt(decryption_materials=decryption_materials, encrypted_data_keys=edk)
    assert not patch_decrypt_on_wrapping_key.called


def test_keyring_trace_on_decrypt_when_data_key_given(raw_aes_keyring):
    test_raw_aes_keyring = raw_aes_keyring
    test = test_raw_aes_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_with_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES],
    )
    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            # Check keyring trace does not contain KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags


@pytest.mark.parametrize(
    "decryption_materials, edk",
    (
        (get_decryption_materials_without_data_encryption_key(), []),
        (get_encryption_materials_without_data_encryption_key(), [_ENCRYPTED_DATA_KEY_NOT_IN_KEYRING]),
    ),
)
def test_on_decrypt_when_data_key_and_edk_not_provided(
    raw_aes_keyring, decryption_materials, edk, patch_decrypt_on_wrapping_key
):
    test_raw_aes_keyring = raw_aes_keyring

    test = test_raw_aes_keyring.on_decrypt(decryption_materials=decryption_materials, encrypted_data_keys=edk)
    assert not patch_decrypt_on_wrapping_key.called

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags

    assert test.data_encryption_key is None


def test_on_decrypt_when_data_key_not_provided_and_edk_provided(raw_aes_keyring, patch_decrypt_on_wrapping_key):
    patch_decrypt_on_wrapping_key.return_value = _DATA_KEY
    test_raw_aes_keyring = raw_aes_keyring
    test_raw_aes_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES],
    )
    patch_decrypt_on_wrapping_key.assert_called_once_with(
        encrypted_wrapped_data_key=mock.ANY, encryption_context=mock.ANY
    )


def test_keyring_trace_when_data_key_not_provided_and_edk_provided(raw_aes_keyring):
    test_raw_aes_keyring = raw_aes_keyring

    test = test_raw_aes_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_encryption_key(),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES],
    )
    decrypted_flag_count = 0

    for keyring_trace in test.keyring_trace:
        if KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY in keyring_trace.flags:
            decrypted_flag_count += 1

    assert decrypted_flag_count == 1


def test_error_when_data_key_not_generated(patch_os_urandom):
    patch_os_urandom.side_effect = NotImplementedError
    with pytest.raises(GenerateKeyError) as exc_info:
        _generate_data_key(
            encryption_materials=get_encryption_materials_without_data_encryption_key(),
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        )
    assert exc_info.match("Unable to generate data encryption key.")


def test_generate_data_key_error_when_data_key_exists():
    with pytest.raises(TypeError) as exc_info:
        _generate_data_key(
            encryption_materials=get_encryption_materials_with_data_encryption_key(),
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        )
    assert exc_info.match("Data encryption key already exists.")


def test_generate_data_key_keyring_trace():
    encryption_materials_without_data_key = EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    )
    _generate_data_key(
        encryption_materials=encryption_materials_without_data_key,
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
    )

    assert encryption_materials_without_data_key.data_encryption_key.key_provider.provider_id == _PROVIDER_ID
    assert encryption_materials_without_data_key.data_encryption_key.key_provider.key_info == _KEY_ID

    generate_flag_count = 0

    for keyring_trace in encryption_materials_without_data_key.keyring_trace:
        if KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY in keyring_trace.flags:
            generate_flag_count += 1
    assert generate_flag_count == 1
