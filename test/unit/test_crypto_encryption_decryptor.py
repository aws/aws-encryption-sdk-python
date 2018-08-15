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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.encryption.Decryptor``."""
import pytest
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.encryption
from aws_encryption_sdk.internal.crypto.encryption import Decryptor, decrypt

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
def patch_decryptor(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.encryption, 'Decryptor')
    yield aws_encryption_sdk.internal.crypto.encryption.Decryptor


def test_decryptor_init(patch_default_backend, patch_cipher):
    mock_algorithm = MagicMock()
    tester = Decryptor(
        algorithm=mock_algorithm,
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv,
        tag=sentinel.tag
    )

    assert tester.source_key is sentinel.key
    mock_algorithm.encryption_algorithm.assert_called_once_with(sentinel.key)
    mock_algorithm.encryption_mode.assert_called_once_with(sentinel.iv, sentinel.tag)
    patch_default_backend.assert_called_once_with()
    patch_cipher.assert_called_once_with(
        mock_algorithm.encryption_algorithm.return_value,
        mock_algorithm.encryption_mode.return_value,
        backend=patch_default_backend.return_value
    )
    patch_cipher.return_value.decryptor.assert_called_once_with()
    assert tester._decryptor is patch_cipher.return_value.decryptor.return_value
    tester._decryptor.authenticate_additional_data.assert_called_once_with(sentinel.aad)


def test_decryptor_update(patch_default_backend, patch_cipher):
    tester = Decryptor(
        algorithm=MagicMock(),
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv,
        tag=sentinel.tag
    )

    test = tester.update(sentinel.ciphertext)

    tester._decryptor.update.assert_called_once_with(sentinel.ciphertext)
    assert test is tester._decryptor.update.return_value


def test_decryptor_finalize(patch_default_backend, patch_cipher):
    tester = Decryptor(
        algorithm=MagicMock(),
        key=sentinel.key,
        associated_data=sentinel.aad,
        iv=sentinel.iv,
        tag=sentinel.tag
    )

    test = tester.finalize()

    tester._decryptor.finalize.assert_called_once_with()
    assert test is tester._decryptor.finalize.return_value


def test_decrypt(patch_decryptor):
    patch_decryptor.return_value.update.return_value = b'some data-'
    patch_decryptor.return_value.finalize.return_value = b'some more data'

    test = decrypt(
        algorithm=sentinel.algorithm,
        key=sentinel.key,
        encrypted_data=MagicMock(
            iv=sentinel.iv,
            tag=sentinel.tag,
            ciphertext=sentinel.ciphertext
        ),
        associated_data=sentinel.aad
    )

    patch_decryptor.assert_called_once_with(
        sentinel.algorithm,
        sentinel.key,
        sentinel.aad,
        sentinel.iv,
        sentinel.tag
    )
    patch_decryptor.return_value.update.assert_called_once_with(sentinel.ciphertext)
    patch_decryptor.return_value.finalize.assert_called_once_with()
    assert test == b'some data-some more data'
