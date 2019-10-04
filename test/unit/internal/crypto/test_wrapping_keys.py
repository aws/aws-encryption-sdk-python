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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.wrapping_keys``."""
import pytest
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.wrapping_keys
from aws_encryption_sdk.exceptions import IncorrectMasterKeyError, InvalidDataKeyError
from aws_encryption_sdk.identifiers import EncryptionKeyType, EncryptionType
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.structures import EncryptedData

from .vectors import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys, "default_backend")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.default_backend


@pytest.yield_fixture
def patch_serialization(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys, "serialization")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.serialization


@pytest.yield_fixture
def patch_derive_data_encryption_key(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys, "derive_data_encryption_key")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.derive_data_encryption_key


@pytest.yield_fixture
def patch_urandom(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys.os, "urandom")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.os.urandom


@pytest.yield_fixture
def patch_serialize_encryption_context(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys, "serialize_encryption_context")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.serialize_encryption_context


@pytest.yield_fixture
def patch_encrypt(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys, "encrypt")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.encrypt


@pytest.yield_fixture
def patch_decrypt(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.wrapping_keys, "decrypt")
    yield aws_encryption_sdk.internal.crypto.wrapping_keys.decrypt


def mock_wrapping_rsa_keys():
    mock_wrapping_rsa_private_key = MagicMock()
    mock_wrapping_rsa_public_key = MagicMock()
    mock_wrapping_rsa_private_key.public_key.return_value = mock_wrapping_rsa_public_key
    return mock_wrapping_rsa_private_key, mock_wrapping_rsa_public_key


def mock_encrypted_data():
    return EncryptedData(iv=VALUES["iv"], ciphertext=VALUES["ciphertext"], tag=VALUES["tag"])


def test_wrapping_key_init_private(patch_default_backend, patch_serialization):
    wrapping_algorithm = MagicMock()
    wrapping_key = MagicMock()
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=wrapping_algorithm, wrapping_key=wrapping_key, wrapping_key_type=EncryptionKeyType.PRIVATE
    )
    assert test_wrapping_key.wrapping_algorithm is wrapping_algorithm
    assert test_wrapping_key.wrapping_key_type is EncryptionKeyType.PRIVATE
    patch_serialization.load_pem_private_key.assert_called_once_with(
        data=wrapping_key, password=None, backend=patch_default_backend.return_value
    )
    assert not patch_serialization.load_pem_public_key.called
    assert test_wrapping_key._wrapping_key is patch_serialization.load_pem_private_key.return_value


def test_wrapping_key_init_private_with_password(patch_default_backend, patch_serialization):
    wrapping_algorithm = MagicMock()
    wrapping_key = MagicMock()
    WrappingKey(
        wrapping_algorithm=wrapping_algorithm,
        wrapping_key=wrapping_key,
        wrapping_key_type=EncryptionKeyType.PRIVATE,
        password=sentinel.password,
    )
    patch_serialization.load_pem_private_key.assert_called_once_with(
        data=wrapping_key, password=sentinel.password, backend=patch_default_backend.return_value
    )


def test_wrapping_key_init_public(patch_default_backend, patch_serialization):
    wrapping_algorithm = MagicMock()
    wrapping_key = MagicMock()
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=wrapping_algorithm, wrapping_key=wrapping_key, wrapping_key_type=EncryptionKeyType.PUBLIC
    )
    patch_serialization.load_pem_public_key.assert_called_once_with(
        data=wrapping_key, backend=patch_default_backend.return_value
    )
    assert not patch_serialization.load_pem_private_key.called
    assert test_wrapping_key._wrapping_key is patch_serialization.load_pem_public_key.return_value


def test_wrapping_key_init_symmetric(patch_default_backend, patch_serialization, patch_derive_data_encryption_key):
    wrapping_algorithm = MagicMock()
    wrapping_key = MagicMock()
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=wrapping_algorithm, wrapping_key=wrapping_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC
    )
    assert not patch_serialization.load_pem_private_key.called
    assert not patch_serialization.load_pem_public_key.called
    assert test_wrapping_key._wrapping_key is wrapping_key
    patch_derive_data_encryption_key.assert_called_once_with(
        source_key=wrapping_key, algorithm=wrapping_algorithm.algorithm, message_id=None
    )
    assert test_wrapping_key._derived_wrapping_key is patch_derive_data_encryption_key.return_value


def test_wrapping_key_init_invalid_key_type():
    with pytest.raises(InvalidDataKeyError) as excinfo:
        WrappingKey(wrapping_algorithm=MagicMock(), wrapping_key=MagicMock(), wrapping_key_type=sentinel.key_type)

    excinfo.match(r"Invalid wrapping_key_type: *")


def test_wrapping_key_encrypt_symmetric(
    patch_default_backend,
    patch_serialization,
    patch_serialize_encryption_context,
    patch_derive_data_encryption_key,
    patch_encrypt,
    patch_urandom,
):
    wrapping_algorithm = MagicMock()
    wrapping_key = MagicMock()
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=wrapping_algorithm, wrapping_key=wrapping_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC
    )

    test = test_wrapping_key.encrypt(
        plaintext_data_key=sentinel.plaintext_data_key, encryption_context=sentinel.encryption_context
    )

    assert not patch_serialization.load_pem_private_key.called
    assert not patch_serialization.load_pem_public_key.called
    patch_serialize_encryption_context.assert_called_once_with(encryption_context=sentinel.encryption_context)
    patch_urandom.assert_called_once_with(wrapping_algorithm.algorithm.iv_len)
    patch_encrypt.assert_called_once_with(
        algorithm=wrapping_algorithm.algorithm,
        key=patch_derive_data_encryption_key.return_value,
        plaintext=sentinel.plaintext_data_key,
        associated_data=patch_serialize_encryption_context.return_value,
        iv=patch_urandom.return_value,
    )
    assert test is patch_encrypt.return_value


def test_wrapping_key_encrypt_private(
    patch_default_backend, patch_serialization, patch_serialize_encryption_context, patch_encrypt
):
    private_key, public_key = mock_wrapping_rsa_keys()
    patch_serialization.load_pem_private_key.return_value = private_key
    public_key.encrypt.return_value = VALUES["ciphertext"]
    mock_wrapping_algorithm = MagicMock(encryption_type=EncryptionType.ASYMMETRIC)
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=mock_wrapping_algorithm,
        wrapping_key=sentinel.wrapping_key,
        wrapping_key_type=EncryptionKeyType.PRIVATE,
    )
    test = test_wrapping_key.encrypt(
        plaintext_data_key=sentinel.plaintext_data_key, encryption_context=sentinel.encryption_context
    )
    private_key.public_key.assert_called_once_with()
    public_key.encrypt.assert_called_once_with(
        plaintext=sentinel.plaintext_data_key, padding=mock_wrapping_algorithm.padding
    )
    assert not patch_serialize_encryption_context.called
    assert not patch_encrypt.called
    assert test == EncryptedData(iv=None, ciphertext=VALUES["ciphertext"], tag=None)


def test_wrapping_key_encrypt_public(
    patch_default_backend, patch_serialization, patch_serialize_encryption_context, patch_encrypt
):
    _, public_key = mock_wrapping_rsa_keys()
    patch_serialization.load_pem_public_key.return_value = public_key
    public_key.encrypt.return_value = VALUES["ciphertext"]
    mock_wrapping_algorithm = MagicMock(encryption_type=EncryptionType.ASYMMETRIC)
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=mock_wrapping_algorithm,
        wrapping_key=sentinel.wrapping_key,
        wrapping_key_type=EncryptionKeyType.PUBLIC,
    )
    test = test_wrapping_key.encrypt(
        plaintext_data_key=sentinel.plaintext_data_key, encryption_context=sentinel.encryption_context
    )
    public_key.encrypt.assert_called_once_with(
        plaintext=sentinel.plaintext_data_key, padding=mock_wrapping_algorithm.padding
    )
    assert not patch_serialize_encryption_context.called
    assert not patch_encrypt.called
    assert test == EncryptedData(iv=None, ciphertext=VALUES["ciphertext"], tag=None)


def test_wrapping_key_decrypt_symmetric(
    patch_default_backend,
    patch_serialization,
    patch_serialize_encryption_context,
    patch_derive_data_encryption_key,
    patch_decrypt,
):
    mock_wrapping_algorithm = MagicMock()
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=mock_wrapping_algorithm,
        wrapping_key=sentinel.wrapping_key,
        wrapping_key_type=EncryptionKeyType.SYMMETRIC,
    )
    test = test_wrapping_key.decrypt(
        encrypted_wrapped_data_key=VALUES["ciphertext"], encryption_context=sentinel.encryption_context
    )
    patch_serialize_encryption_context.assert_called_once_with(encryption_context=sentinel.encryption_context)
    patch_decrypt.assert_called_once_with(
        algorithm=mock_wrapping_algorithm.algorithm,
        key=patch_derive_data_encryption_key.return_value,
        encrypted_data=VALUES["ciphertext"],
        associated_data=patch_serialize_encryption_context.return_value,
    )
    assert test is patch_decrypt.return_value


def test_wrapping_key_decrypt_private(
    patch_default_backend, patch_serialization, patch_serialize_encryption_context, patch_decrypt
):
    private_key, _ = mock_wrapping_rsa_keys()
    patch_serialization.load_pem_private_key.return_value = private_key
    private_key.decrypt.return_value = sentinel.plaintext_data
    mock_wrapping_algorithm = MagicMock(encryption_type=EncryptionType.ASYMMETRIC)
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=mock_wrapping_algorithm,
        wrapping_key=sentinel.wrapping_key,
        wrapping_key_type=EncryptionKeyType.PRIVATE,
    )
    test = test_wrapping_key.decrypt(
        encrypted_wrapped_data_key=mock_encrypted_data(), encryption_context=sentinel.encryption_context
    )
    private_key.decrypt.assert_called_once_with(
        ciphertext=VALUES["ciphertext"], padding=mock_wrapping_algorithm.padding
    )
    assert not patch_serialize_encryption_context.called
    assert not patch_decrypt.called
    assert test is sentinel.plaintext_data


def test_wrapping_key_decrypt_public(
    patch_default_backend, patch_serialization, patch_serialize_encryption_context, patch_decrypt
):
    private_key, _ = mock_wrapping_rsa_keys()
    patch_serialization.load_pem_private_key.return_value = private_key
    private_key.decrypt.return_value = sentinel.plaintext_data
    mock_wrapping_algorithm = MagicMock(encryption_type=EncryptionType.ASYMMETRIC)
    test_wrapping_key = WrappingKey(
        wrapping_algorithm=mock_wrapping_algorithm,
        wrapping_key=sentinel.wrapping_key,
        wrapping_key_type=EncryptionKeyType.PUBLIC,
    )
    with pytest.raises(IncorrectMasterKeyError) as excinfo:
        test_wrapping_key.decrypt(
            encrypted_wrapped_data_key=mock_encrypted_data(), encryption_context=sentinel.encryption_context
        )

    excinfo.match(r"Public key cannot decrypt")
