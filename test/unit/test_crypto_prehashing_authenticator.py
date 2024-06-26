# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for ``aws_encryption_sdk.internal.crypto._PrehashingAuthenticater``."""
import pytest
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.authentication
from aws_encryption_sdk.exceptions import NotSupportedError
from aws_encryption_sdk.internal.crypto.authentication import _PrehashingAuthenticator

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_set_signature_type(mocker):
    mocker.patch.object(_PrehashingAuthenticator, "_set_signature_type")
    yield _PrehashingAuthenticator._set_signature_type


@pytest.fixture
def patch_build_hasher(mocker):
    mocker.patch.object(_PrehashingAuthenticator, "_build_hasher")
    yield _PrehashingAuthenticator._build_hasher


@pytest.fixture
def patch_cryptography_ec(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "ec")
    yield aws_encryption_sdk.internal.crypto.authentication.ec


@pytest.fixture
def patch_cryptography_hashes(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "hashes")
    yield aws_encryption_sdk.internal.crypto.authentication.hashes


@pytest.fixture
def patch_cryptography_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "default_backend")
    yield aws_encryption_sdk.internal.crypto.authentication.default_backend


def test_init(patch_set_signature_type, patch_build_hasher):
    test = _PrehashingAuthenticator(algorithm=sentinel.algorithm, key=sentinel.key)

    assert test.algorithm is sentinel.algorithm
    patch_set_signature_type.assert_called_once_with()
    assert test._signature_type is patch_set_signature_type.return_value
    assert test.key is sentinel.key
    patch_build_hasher.assert_called_once_with()
    assert test._hasher is patch_build_hasher.return_value


def test_set_signature_type_elliptic_curve(
    patch_build_hasher, patch_cryptography_ec
):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_cryptography_ec.EllipticCurve)
    mock_algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)
    test = _PrehashingAuthenticator(algorithm=mock_algorithm, key=sentinel.key)

    assert test._signature_type is patch_cryptography_ec.EllipticCurve


def test_set_signature_type_unknown(
    patch_build_hasher, patch_cryptography_ec
):
    with pytest.raises(NotSupportedError) as excinfo:
        _PrehashingAuthenticator(algorithm=MagicMock(), key=sentinel.key)

    excinfo.match(r"Unsupported signing algorithm info")


def test_build_hasher(patch_set_signature_type, patch_cryptography_hashes, patch_cryptography_default_backend):
    mock_algorithm = MagicMock()
    test = _PrehashingAuthenticator(algorithm=mock_algorithm, key=sentinel.key)

    patch_cryptography_hashes.Hash.assert_called_once_with(
        mock_algorithm.signing_hash_type.return_value, backend=patch_cryptography_default_backend.return_value
    )
    assert test._hasher is patch_cryptography_hashes.Hash.return_value
