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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto._PrehashingAuthenticater``."""
import pytest
from cryptography.utils import InterfaceNotImplemented
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.authentication
from aws_encryption_sdk.exceptions import NotSupportedError
from aws_encryption_sdk.internal.crypto.authentication import _PrehashingAuthenticator

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_set_signature_type(mocker):
    mocker.patch.object(_PrehashingAuthenticator, "_set_signature_type")
    yield _PrehashingAuthenticator._set_signature_type


@pytest.yield_fixture
def patch_build_hasher(mocker):
    mocker.patch.object(_PrehashingAuthenticator, "_build_hasher")
    yield _PrehashingAuthenticator._build_hasher


@pytest.yield_fixture
def patch_cryptography_utils_verify_interface(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "verify_interface")
    yield aws_encryption_sdk.internal.crypto.authentication.verify_interface


@pytest.yield_fixture
def patch_cryptography_ec(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "ec")
    yield aws_encryption_sdk.internal.crypto.authentication.ec


@pytest.yield_fixture
def patch_cryptography_hashes(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "hashes")
    yield aws_encryption_sdk.internal.crypto.authentication.hashes


@pytest.yield_fixture
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
    patch_build_hasher, patch_cryptography_utils_verify_interface, patch_cryptography_ec
):
    mock_algorithm = MagicMock()
    test = _PrehashingAuthenticator(algorithm=mock_algorithm, key=sentinel.key)

    patch_cryptography_utils_verify_interface.assert_called_once_with(
        patch_cryptography_ec.EllipticCurve, mock_algorithm.signing_algorithm_info
    )
    assert test._signature_type is patch_cryptography_ec.EllipticCurve


def test_set_signature_type_unknown(
    patch_build_hasher, patch_cryptography_utils_verify_interface, patch_cryptography_ec
):
    patch_cryptography_utils_verify_interface.side_effect = InterfaceNotImplemented
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
