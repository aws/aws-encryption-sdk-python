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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.encryption.Encryptor``."""
from mock import MagicMock, sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.encryption
from aws_encryption_sdk.internal.crypto.encryption import encrypt, Encryptor
from aws_encryption_sdk.internal.structures import EncryptedData

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.encryption, 'default_backend')
    yield aws_encryption_sdk.internal.crypto.encryption.default_backend


@pytest.yield_fixture
def patch_cipher(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.encryption, 'Cipher')
    yield aws_encryption_sdk.internal.crypto.encryption.Cipher


@pytest.yield_fixture
def patch_encryptor(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.encryption, 'Encryptor')
    yield aws_encryption_sdk.internal.crypto.encryption.Encryptor


def test_encryptor_init(patch_default_backend, patch_cipher):
    mock_algorithm = MagicMock()
    tester = Encryptor(
        algorithm=mock_algorithm,
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv
    )

    assert tester.source_key is sentinel.key
    mock_algorithm.encryption_algorithm.assert_called_once_with(sentinel.key)
    mock_algorithm.encryption_mode.assert_called_once_with(sentinel.iv)
    patch_default_backend.assert_called_once_with()
    patch_cipher.assert_called_once_with(
        mock_algorithm.encryption_algorithm.return_value,
        mock_algorithm.encryption_mode.return_value,
        backend=patch_default_backend.return_value
    )
    patch_cipher.return_value.encryptor.assert_called_once_with()
    assert tester._encryptor is patch_cipher.return_value.encryptor.return_value
    tester._encryptor.authenticate_additional_data.assert_called_once_with(sentinel.aad)


def test_encryptor_update(patch_default_backend, patch_cipher):
    tester = Encryptor(
        algorithm=MagicMock(),
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv
    )

    test = tester.update(sentinel.plaintext)

    tester._encryptor.update.assert_called_once_with(sentinel.plaintext)
    assert test is tester._encryptor.update.return_value


def test_encryptor_finalize(patch_default_backend, patch_cipher):
    tester = Encryptor(
        algorithm=MagicMock(),
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv
    )

    test = tester.finalize()

    tester._encryptor.finalize.assert_called_once_with()
    assert test is tester._encryptor.finalize.return_value


def test_encryptor_tag(patch_default_backend, patch_cipher):
    tester = Encryptor(
        algorithm=MagicMock(),
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv
    )

    test = tester.tag

    assert test is tester._encryptor.tag


def test_encrypt(patch_encryptor):
    patch_encryptor.return_value.update.return_value = b'some data-'
    patch_encryptor.return_value.finalize.return_value = b'some more data'
    patch_encryptor.return_value.iv = b'ex iv'
    patch_encryptor.return_value.tag = b'ex tag'
    test = encrypt(
        algorithm=sentinel.algorithm,
        key=sentinel.key,
        plaintext=sentinel.plaintext,
        associated_data=sentinel.aad,
        iv=sentinel.iv
    )

    patch_encryptor.assert_called_once_with(
        sentinel.algorithm,
        sentinel.key,
        sentinel.aad,
        sentinel.iv
    )
    patch_encryptor.return_value.update.assert_called_once_with(sentinel.plaintext)
    patch_encryptor.return_value.finalize.assert_called_once_with()
    assert test == EncryptedData(
        iv=b'ex iv',
        ciphertext=b'some data-some more data',
        tag=b'ex tag'
    )
