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
from mock import MagicMock, patch, sentinel, Mock

from aws_encryption_sdk.identifiers import KeyringTraceFlag, WrappingAlgorithm, Algorithm
from aws_encryption_sdk.keyring.base import EncryptedDataKey, Keyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, generate_data_key, GenerateKeyError
from aws_encryption_sdk.structures import MasterKeyInfo
from aws_encryption_sdk.materials_managers import EncryptionMaterials
from .test_utils import _ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY, _ENCRYPTION_MATERIALS_WITH_DATA_KEY, _PROVIDER_ID, \
    _WRAPPING_KEY, _DATA_KEY, _KEY_ID, _DECRYPTION_MATERIALS_WITH_DATA_KEY, _DECRYPTION_MATERIALS_WITHOUT_DATA_KEY, \
    _ENCRYPTION_CONTEXT, _ENCRYPTED_DATA_KEY_AES, _SIGNING_KEY

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_parent():
    assert issubclass(RawAESKeyring, Keyring)


def test_valid_parameters():
    test = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )
    assert test.key_name == _KEY_ID
    assert test.key_namespace == _PROVIDER_ID
    assert test._wrapping_algorithm == WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
    assert test._wrapping_key == _WRAPPING_KEY


def test_missing_required_parameters():
    with pytest.raises(Exception) as exc_info:
        RawAESKeyring(
            key_namespace=_PROVIDER_ID,
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        )
    assert exc_info.errisinstance(TypeError)


def test_invalid_values_as_parameter():
    with pytest.raises(Exception) as exc_info:
        RawAESKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        )
    assert exc_info.errisinstance(TypeError)


@patch("aws_encryption_sdk.keyring.raw_keyring.generate_data_key")
def test_on_encrypt_when_data_encryption_key_given(mock_generate_data_key):
    mock_generate_data_key.return_value = _DATA_KEY
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    test = test_raw_aes_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITH_DATA_KEY)
    # Check if keyring is generated
    assert not mock_generate_data_key.called


def test_keyring_trace_on_encrypt_when_data_encryption_key_given():
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    test = test_raw_aes_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITH_DATA_KEY)

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            # Check keyring trace does not contain KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
            assert KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY not in keyring_trace.flags


def test_on_encrypt_when_data_encryption_key_not_given():
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    original_number_of_encrypted_data_keys = len(_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY.encrypted_data_keys)

    test = test_raw_aes_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)

    # Check if data key is generated
    assert test.data_encryption_key and test.data_encryption_key is not None

    generated_flag_count = 0
    encrypted_flag_count = 0

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID and KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY \
                in keyring_trace.flags:
            # Check keyring trace contains KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
            generated_flag_count += 1
        if KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY in keyring_trace.flags:
            encrypted_flag_count += 1

    assert generated_flag_count == 1

    assert len(test.encrypted_data_keys) == original_number_of_encrypted_data_keys + 1

    assert encrypted_flag_count == 1


@patch("aws_encryption_sdk.internal.crypto.wrapping_keys.WrappingKey.decrypt")
def test_on_decrypt_when_data_key_given(mock_decrypt):
    mock_decrypt.return_value = _DATA_KEY
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )
    test = test_raw_aes_keyring.on_decrypt(
        decryption_materials=_DECRYPTION_MATERIALS_WITH_DATA_KEY, encrypted_data_keys=[
                                               EncryptedDataKey(
                                                key_provider=MasterKeyInfo(
                                                    provider_id=_PROVIDER_ID,
                                                    key_info=_KEY_ID),
                                                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\
                                                xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                                                b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\
                                                x07FzE\xde",
                                                )
                                            ]
    )
    assert not mock_decrypt.called


def test_keyring_trace_on_decrypt_when_data_key_given():
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )
    test = test_raw_aes_keyring.on_decrypt(
        decryption_materials=_DECRYPTION_MATERIALS_WITH_DATA_KEY, encrypted_data_keys=[
                                               EncryptedDataKey(
                                                key_provider=MasterKeyInfo(
                                                    provider_id=_PROVIDER_ID,
                                                    key_info=_KEY_ID),
                                                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\
                                                xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                                                b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\
                                                x07FzE\xde",
                                                )
                                            ]
    )
    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            # Check keyring trace does not contain KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags


@patch("aws_encryption_sdk.internal.crypto.wrapping_keys.WrappingKey.decrypt")
def test_on_decrypt_when_data_key_and_edk_not_provided(mock_decrypt):
    mock_decrypt.return_value = _DATA_KEY
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    test = test_raw_aes_keyring.on_decrypt(decryption_materials=_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY,
                                           encrypted_data_keys=[])
    assert not mock_decrypt.called

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags

    assert test.data_encryption_key is None


@patch("aws_encryption_sdk.internal.crypto.wrapping_keys.WrappingKey.decrypt")
def test_on_decrypt_when_data_key_not_provided_and_edk_not_in_keyring(mock_decrypt):
    mock_decrypt.return_value = _DATA_KEY
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    test = test_raw_aes_keyring.on_decrypt(decryption_materials=_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY,
                                           encrypted_data_keys=[
                                               EncryptedDataKey(
                                                   key_provider=MasterKeyInfo(
                                                       provider_id=_PROVIDER_ID,
                                                       key_info=b"5430b043-5843-4629-869c-64794af77ada"),
                                                   encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\
                                                                    xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                                                                      b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\
                                                                      x81\xf7\xf4G\
                                                                    x07FzE\xde",
                                               )
                                           ]
                                           )
    assert not mock_decrypt.called

    for keyring_trace in test.keyring_trace:
        if keyring_trace.wrapping_key.key_info == _KEY_ID:
            assert KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY not in keyring_trace.flags

    assert test.data_encryption_key is None


@patch("aws_encryption_sdk.internal.crypto.wrapping_keys.WrappingKey.decrypt")
def test_on_decrypt_when_data_key_not_provided_and_edk_provided(mock_decrypt):
    mock_decrypt.return_value = _DATA_KEY
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    test = test_raw_aes_keyring.on_decrypt(decryption_materials=_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY,
                                           encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES]
                                           )
    assert mock_decrypt.called_once_with(encrypted_wrapped_data_key=_ENCRYPTED_DATA_KEY_AES,
                                         encryption_context=_ENCRYPTION_CONTEXT
                                         )


def test_keyring_trace_when_data_key_not_provided_and_edk_provided():
    test_raw_aes_keyring = RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY,
    )

    test = test_raw_aes_keyring.on_decrypt(decryption_materials=_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY,
                                           encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES]
                                           )
    decrypted_flag_count = 0

    for keyring_trace in test.keyring_trace:
        if KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY in keyring_trace.flags:
            decrypted_flag_count += 1

    assert decrypted_flag_count == 1


# @patch("aws_encryption_sdk.key_providers.raw.os.urandom")
# def test_error_when_data_key_not_generated(mock_os_urandom):
#     mock_os_urandom.side_effect = Exception()
#     test_raw_aes_keyring = RawAESKeyring(
#         key_namespace=_PROVIDER_ID,
#         key_name=_KEY_ID,
#         wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
#         wrapping_key=_WRAPPING_KEY,
#     )
#     with pytest.raises(GenerateKeyError) as exc_info:
#         test_raw_aes_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)
#     assert exc_info.match("Unable to generate data encryption key.")


def test_generate_data_key_error_when_data_key_exists():
    with pytest.raises(TypeError) as exc_info:
        generate_data_key(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY,
                          key_provider=MasterKeyInfo(
                              provider_id=_PROVIDER_ID,
                              key_info=_KEY_ID
                          )
                          )
    assert exc_info.match("Data encryption key already exists.")


def test_generate_data_key_keyring_trace():
    encryption_materials_without_data_key = EncryptionMaterials(
                                                algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                                                encryption_context=_ENCRYPTION_CONTEXT,
                                                signing_key=_SIGNING_KEY,
                                            )
    plaintext = generate_data_key(encryption_materials=encryption_materials_without_data_key,
                                  key_provider=MasterKeyInfo(
                                      provider_id=_PROVIDER_ID,
                                      key_info=_KEY_ID
                                    )
                                  )

    generate_flag_count = 0
    for keyring_trace in encryption_materials_without_data_key.keyring_trace:
        if KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY in keyring_trace.flags:
            generate_flag_count += 1
    assert generate_flag_count == 1
