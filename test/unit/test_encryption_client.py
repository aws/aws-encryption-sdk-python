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
import pytest
from mock import MagicMock

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_init_defaults():
    test = aws_encryption_sdk.EncryptionSDKClient()
    assert test.config.commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT


def test_init_success():
    test = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    assert test.config.commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT


def test_client_encrypt(mocker):
    mocker.patch.object(aws_encryption_sdk, "StreamEncryptor")
    cmm = MagicMock(__class__=CryptoMaterialsManager)
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

    kwargs = dict()
    kwargs["source"] = b"plaintext"
    kwargs["materials_manager"] = cmm
    client.encrypt(**kwargs)
    expected_kwargs = kwargs.copy()
    expected_kwargs["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    aws_encryption_sdk.StreamEncryptor.assert_called_once_with(**expected_kwargs)


def test_client_decrypt(mocker):
    mocker.patch.object(aws_encryption_sdk, "StreamDecryptor")
    cmm = MagicMock(__class__=CryptoMaterialsManager)
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

    kwargs = dict()
    kwargs["source"] = b"ciphertext"
    kwargs["materials_manager"] = cmm
    client.decrypt(**kwargs)
    expected_kwargs = kwargs.copy()
    expected_kwargs["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
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
    aws_encryption_sdk.StreamDecryptor.assert_called_once_with(**expected_kwargs)
