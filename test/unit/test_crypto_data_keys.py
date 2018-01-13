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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.data_keys``."""
from mock import MagicMock, sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.data_keys
from aws_encryption_sdk.internal.crypto.data_keys import derive_data_encryption_key

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.data_keys, 'default_backend')
    yield aws_encryption_sdk.internal.crypto.data_keys.default_backend


@pytest.yield_fixture
def patch_struct(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.data_keys, 'struct')
    yield aws_encryption_sdk.internal.crypto.data_keys.struct


def test_derive_data_encryption_key_with_hkdf(patch_default_backend, patch_struct):
    algorithm = MagicMock()
    algorithm.kdf_hash_type.return_value = sentinel.kdf_hash_type
    test = derive_data_encryption_key(
        source_key=sentinel.source_key,
        algorithm=algorithm,
        message_id=sentinel.message_id
    )
    patch_struct.pack.assert_called_with(
        '>H16s',
        algorithm.algorithm_id,
        sentinel.message_id
    )
    algorithm.kdf_type.assert_called_with(
        algorithm=sentinel.kdf_hash_type,
        length=algorithm.data_key_len,
        salt=None,
        info=patch_struct.pack.return_value,
        backend=patch_default_backend.return_value
    )
    algorithm.kdf_type.return_value.derive.assert_called_with(
        sentinel.source_key
    )
    assert test == algorithm.kdf_type.return_value.derive.return_value


def test_derive_data_encryption_key_no_hkdf(patch_default_backend):
    algorithm = MagicMock(kdf_type=None)
    test = derive_data_encryption_key(
        source_key=sentinel.source_key,
        algorithm=algorithm,
        message_id=sentinel.message_id
    )
    assert test == sentinel.source_key
