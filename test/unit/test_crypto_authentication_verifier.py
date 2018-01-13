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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.authentication.Verifier``."""
from mock import MagicMock, sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.authentication
from aws_encryption_sdk.internal.crypto.authentication import Verifier
from aws_encryption_sdk.internal.defaults import ALGORITHM
from .test_crypto import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, 'default_backend')
    yield aws_encryption_sdk.internal.crypto.authentication.default_backend


@pytest.yield_fixture
def patch_serialization(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, 'serialization')
    yield aws_encryption_sdk.internal.crypto.authentication.serialization


@pytest.yield_fixture
def patch_ecc_public_numbers_from_compressed_point(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, '_ecc_public_numbers_from_compressed_point')
    yield aws_encryption_sdk.internal.crypto.authentication._ecc_public_numbers_from_compressed_point


@pytest.yield_fixture
def patch_ec(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, 'ec')
    yield aws_encryption_sdk.internal.crypto.authentication.ec


@pytest.yield_fixture
def patch_prehashed(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, 'Prehashed')
    yield aws_encryption_sdk.internal.crypto.authentication.Prehashed


@pytest.yield_fixture
def patch_base64(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, 'base64')
    yield aws_encryption_sdk.internal.crypto.authentication.base64


@pytest.yield_fixture
def patch_build_hasher(mocker):
    mocker.patch.object(Verifier, '_build_hasher')
    yield Verifier._build_hasher


@pytest.yield_fixture
def patch_set_signature_type(mocker):
    mocker.patch.object(Verifier, '_set_signature_type')
    yield Verifier._set_signature_type


def test_f_verifier_from_key_bytes():
    check = Verifier(
        algorithm=ALGORITHM,
        key=VALUES['ecc_private_key_prime'].public_key()
    )
    test = Verifier.from_key_bytes(
        algorithm=ALGORITHM,
        key_bytes=VALUES['ecc_private_key_prime_public_bytes']
    )
    assert check.key.public_numbers() == test.key.public_numbers()


def test_f_verifier_key_bytes():
    test = Verifier(
        algorithm=ALGORITHM,
        key=VALUES['ecc_private_key_prime'].public_key()
    )
    assert test.key_bytes() == VALUES['ecc_private_key_prime_public_bytes']


def test_verifier_from_encoded_point(
        patch_default_backend,
        patch_serialization,
        patch_ecc_public_numbers_from_compressed_point,
        patch_base64,
        patch_build_hasher
):
    mock_point_instance = MagicMock()
    mock_point_instance.public_key.return_value = sentinel.public_key
    patch_ecc_public_numbers_from_compressed_point.return_value = mock_point_instance
    patch_base64.b64decode.return_value = sentinel.compressed_point
    algorithm = MagicMock()

    verifier = Verifier.from_encoded_point(algorithm=algorithm, encoded_point=sentinel.encoded_point)

    patch_base64.b64decode.assert_called_once_with(sentinel.encoded_point)
    algorithm.signing_algorithm_info.assert_called_once_with()
    patch_ecc_public_numbers_from_compressed_point.assert_called_once_with(
        curve=algorithm.signing_algorithm_info.return_value,
        compressed_point=sentinel.compressed_point
    )
    mock_point_instance.public_key.assert_called_once_with(patch_default_backend.return_value)
    assert isinstance(verifier, Verifier)


def test_verifier_update(patch_default_backend, patch_serialization, patch_build_hasher):
    verifier = Verifier(algorithm=MagicMock(), key=MagicMock())
    verifier.update(sentinel.data)
    verifier._hasher.update.assert_called_once_with(sentinel.data)


def test_verifier_verify(
        patch_default_backend,
        patch_serialization,
        patch_ec,
        patch_prehashed,
        patch_build_hasher,
        patch_set_signature_type
):
    algorithm = MagicMock()
    public_key = MagicMock()

    verifier = Verifier(algorithm=algorithm, key=public_key)
    verifier.verify(sentinel.signature)

    verifier._hasher.finalize.assert_called_once_with()
    algorithm.signing_hash_type.assert_called_once_with()
    patch_prehashed.assert_called_once_with(algorithm.signing_hash_type.return_value)
    patch_ec.ECDSA.assert_called_once_with(patch_prehashed.return_value)
    public_key.verify.assert_called_once_with(
        signature=sentinel.signature,
        data=verifier._hasher.finalize.return_value,
        signature_algorithm=patch_ec.ECDSA.return_value
    )
