# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit test suite for aws_encryption_sdk.EncryptionSDKClient"""
import warnings

import pytest
from mock import MagicMock

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.utils.signature import SignaturePolicy
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_init_defaults():
    test = aws_encryption_sdk.EncryptionSDKClient()
    assert test.config.commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    assert test.config.max_encrypted_data_keys is None


def test_init_success():
    test = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        max_encrypted_data_keys=1,
    )
    assert test.config.commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    assert test.config.max_encrypted_data_keys == 1


@pytest.mark.parametrize("max_encrypted_data_keys", (1, 10, 2 ** 16 - 1, 2 ** 16))
def test_init_valid_max_encrypted_data_keys(max_encrypted_data_keys):
    test = aws_encryption_sdk.EncryptionSDKClient(max_encrypted_data_keys=max_encrypted_data_keys)
    assert test.config.max_encrypted_data_keys == max_encrypted_data_keys


@pytest.mark.parametrize("max_encrypted_data_keys", (0, -1))
def test_init_invalid_max_encrypted_data_keys(max_encrypted_data_keys):
    with pytest.raises(ValueError) as exc_info:
        aws_encryption_sdk.EncryptionSDKClient(max_encrypted_data_keys=max_encrypted_data_keys)
    exc_info.match("max_encrypted_data_keys cannot be less than 1")


def test_client_encrypt(mocker):
    mocker.patch.object(aws_encryption_sdk, "StreamEncryptor")
    cmm = MagicMock(__class__=CryptoMaterialsManager)
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, max_encrypted_data_keys=3
    )

    kwargs = dict()
    kwargs["source"] = b"plaintext"
    kwargs["materials_manager"] = cmm
    client.encrypt(**kwargs)
    expected_kwargs = kwargs.copy()
    expected_kwargs["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["signature_policy"] = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["max_encrypted_data_keys"] = 3
    aws_encryption_sdk.StreamEncryptor.assert_called_once_with(**expected_kwargs)


def test_client_decrypt(mocker):
    mocker.patch.object(aws_encryption_sdk, "StreamDecryptor")
    cmm = MagicMock(__class__=CryptoMaterialsManager)
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, max_encrypted_data_keys=3
    )

    kwargs = dict()
    kwargs["source"] = b"ciphertext"
    kwargs["materials_manager"] = cmm
    client.decrypt(**kwargs)
    expected_kwargs = kwargs.copy()
    expected_kwargs["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["signature_policy"] = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["max_encrypted_data_keys"] = 3
    aws_encryption_sdk.StreamDecryptor.assert_called_once_with(**expected_kwargs)


@pytest.mark.parametrize("mode_string", ("e", "encrypt", "ENCRYPT"))
def test_client_stream_encrypt(mocker, mode_string):
    mocker.patch.object(aws_encryption_sdk, "StreamEncryptor")
    cmm = MagicMock(__class__=CryptoMaterialsManager)
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

    kwargs = dict()
    kwargs["mode"] = mode_string
    kwargs["source"] = b"plaintext"
    kwargs["materials_manager"] = cmm
    client.stream(**kwargs)
    expected_kwargs = kwargs.copy()
    expected_kwargs.pop("mode")
    expected_kwargs["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["signature_policy"] = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["max_encrypted_data_keys"] = None
    aws_encryption_sdk.StreamEncryptor.assert_called_once_with(**expected_kwargs)


@pytest.mark.parametrize("mode_string", ("d", "decrypt", "DECRYPT"))
def test_client_stream_decrypt(mocker, mode_string):
    mocker.patch.object(aws_encryption_sdk, "StreamDecryptor")
    cmm = MagicMock(__class__=CryptoMaterialsManager)
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

    kwargs = dict()
    kwargs["mode"] = mode_string
    kwargs["source"] = b"ciphertext"
    kwargs["materials_manager"] = cmm
    client.stream(**kwargs)
    expected_kwargs = kwargs.copy()
    expected_kwargs.pop("mode")
    expected_kwargs["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["signature_policy"] = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT
    expected_kwargs["max_encrypted_data_keys"] = None
    aws_encryption_sdk.StreamDecryptor.assert_called_once_with(**expected_kwargs)


@pytest.mark.parametrize("method", ("encrypt", "decrypt", "stream"))
@pytest.mark.parametrize("key", ("commitment_policy", "max_encrypted_data_keys"))
def test_client_bad_kwargs(mocker, method, key):
    mocker.patch.object(aws_encryption_sdk, "StreamEncryptor")

    cmm = MagicMock(__class__=CryptoMaterialsManager)
    kwargs = dict()
    kwargs[key] = "foobar"
    kwargs["source"] = b"ciphertext"
    kwargs["materials_manager"] = cmm
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        client.encrypt(**kwargs)
        assert len(w) == 1
        assert issubclass(w[-1].category, UserWarning)

        message = str(w[-1].message)
        assert "Invalid keyword argument" in message
        assert "Set this value by passing a 'config' to the EncryptionSDKClient constructor instead" in message
