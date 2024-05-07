# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.data_keys``."""
import pytest
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk.internal.crypto import data_keys

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_default_backend(mocker):
    mocker.patch.object(data_keys, "default_backend")
    yield data_keys.default_backend


@pytest.fixture
def patch_struct(mocker):
    mocker.patch.object(data_keys, "struct")
    yield data_keys.struct


def test_derive_data_encryption_key_with_hkdf(patch_default_backend, patch_struct):
    algorithm = MagicMock()
    algorithm.kdf_hash_type.return_value = sentinel.kdf_hash_type
    algorithm.is_committing.return_value = False
    test = data_keys.derive_data_encryption_key(
        source_key=sentinel.source_key, algorithm=algorithm, message_id=sentinel.message_id
    )
    patch_struct.pack.assert_called_with(">H16s", algorithm.algorithm_id, sentinel.message_id)
    algorithm.kdf_type.assert_called_with(
        algorithm=sentinel.kdf_hash_type,
        length=algorithm.data_key_len,
        salt=None,
        info=patch_struct.pack.return_value,
        backend=patch_default_backend.return_value,
    )
    algorithm.kdf_type.return_value.derive.assert_called_with(sentinel.source_key)
    assert test == algorithm.kdf_type.return_value.derive.return_value


def test_derive_data_encryption_key_with_hkdf_committing(patch_default_backend, patch_struct):
    algorithm = MagicMock()
    algorithm.kdf_hash_type.return_value = sentinel.kdf_hash_type
    algorithm.data_key_len = sentinel.data_key_len
    algorithm.is_committing.return_value = True
    test = data_keys.derive_data_encryption_key(
        source_key=sentinel.source_key, algorithm=algorithm, message_id=sentinel.message_id
    )
    patch_struct.pack.assert_called_with(">H9s", algorithm.algorithm_id, data_keys.KEY_LABEL)
    algorithm.kdf_type.assert_called_with(
        algorithm=sentinel.kdf_hash_type,
        length=sentinel.data_key_len,
        salt=sentinel.message_id,
        info=patch_struct.pack.return_value,
        backend=patch_default_backend.return_value,
    )
    algorithm.kdf_type.return_value.derive.assert_called_with(sentinel.source_key)
    assert test == algorithm.kdf_type.return_value.derive.return_value


def test_derive_data_encryption_key_no_hkdf():
    algorithm = MagicMock(kdf_type=None)
    test = data_keys.derive_data_encryption_key(
        source_key=sentinel.source_key, algorithm=algorithm, message_id=sentinel.message_id
    )
    assert test == sentinel.source_key


def test_calculate_commitment_key(patch_default_backend, patch_struct):
    algorithm = MagicMock()
    algorithm.kdf_hash_type.return_value = sentinel.kdf_hash_type
    algorithm.is_committing.return_value = False
    test = data_keys.calculate_commitment_key(
        source_key=sentinel.source_key, algorithm=algorithm, message_id=sentinel.message_id
    )
    patch_struct.pack.assert_called_with(">9s", data_keys.COMMIT_LABEL)
    algorithm.kdf_type.assert_called_with(
        algorithm=sentinel.kdf_hash_type,
        length=data_keys.L_C,
        salt=sentinel.message_id,
        info=patch_struct.pack.return_value,
        backend=patch_default_backend.return_value,
    )
    algorithm.kdf_type.return_value.derive.assert_called_with(sentinel.source_key)
    assert test == algorithm.kdf_type.return_value.derive.return_value
