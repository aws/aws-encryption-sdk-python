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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.authentication.Signer``."""
import pytest
from mock import MagicMock, sentinel, patch
import cryptography.hazmat.primitives.serialization
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.authentication
from aws_encryption_sdk.internal.crypto.authentication import Signer
from aws_encryption_sdk.internal.defaults import ALGORITHM

from .test_crypto import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "default_backend")
    yield aws_encryption_sdk.internal.crypto.authentication.default_backend


@pytest.fixture
def patch_ec(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "ec")
    yield aws_encryption_sdk.internal.crypto.authentication.ec


@pytest.fixture
def patch_serialization(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "serialization")
    yield aws_encryption_sdk.internal.crypto.authentication.serialization


@pytest.fixture
def patch_ecc_encode_compressed_point(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "_ecc_encode_compressed_point")
    yield aws_encryption_sdk.internal.crypto.authentication._ecc_encode_compressed_point


@pytest.fixture
def patch_ecc_static_length_signature(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "_ecc_static_length_signature")
    yield aws_encryption_sdk.internal.crypto.authentication._ecc_static_length_signature


@pytest.fixture
def patch_base64(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.authentication, "base64")
    yield aws_encryption_sdk.internal.crypto.authentication.base64


@pytest.fixture
def patch_build_hasher(mocker):
    mocker.patch.object(Signer, "_build_hasher")
    yield Signer._build_hasher


def test_f_signer_from_key_bytes():
    check = Signer(algorithm=ALGORITHM, key=VALUES["ecc_private_key_prime"])
    test = Signer.from_key_bytes(algorithm=ALGORITHM, key_bytes=VALUES["ecc_private_key_prime_private_bytes"])
    assert check.key.private_numbers().private_value == test.key.private_numbers().private_value


def test_f_signer_key_bytes():
    test = Signer(algorithm=ALGORITHM, key=VALUES["ecc_private_key_prime"])
    assert test.key_bytes() == VALUES["ecc_private_key_prime_private_bytes"]
    

def test_GIVEN_no_encoding_WHEN_signer_from_key_bytes_THEN_load_der_private_key(
    patch_default_backend,
    patch_build_hasher,
    patch_ec
):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    _algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)

    # Make a new patched serialization module for this test.
    # The default patch introduces serialization as `serialization.Encoding.DER`
    # from within the src, but is `Encoding.DER` in the test.
    # This namespace change causes the src's `isinstance` checks to fail.
    # Mock the `serialization.Encoding.DER`
    with patch.object(cryptography.hazmat.primitives, "serialization"):
        # Mock the `serialization.load_der_private_key`
        with patch.object(aws_encryption_sdk.internal.crypto.authentication.serialization, "load_der_private_key") as mock_der:
            # When: from_key_bytes
            Signer.from_key_bytes(
                algorithm=_algorithm,
                key_bytes=sentinel.key_bytes,
                # Given: No encoding provided => default arg
            )

            # Then: calls load_der_private_key
            mock_der.assert_called_once_with(
                data=sentinel.key_bytes, password=None, backend=patch_default_backend.return_value
            )

    
def test_GIVEN_PEM_encoding_WHEN_signer_from_key_bytes_THEN_load_pem_private_key(
    patch_default_backend,
    patch_serialization,
    patch_build_hasher,
    patch_ec
):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    _algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)

    # When: from_key_bytes
    signer = Signer.from_key_bytes(
        algorithm=_algorithm,
        key_bytes=sentinel.key_bytes,
        # Given: PEM encoding
        encoding=patch_serialization.Encoding.PEM
    )

    # Then: calls load_pem_private_key
    patch_serialization.load_pem_private_key.assert_called_once_with(
        data=sentinel.key_bytes, password=None, backend=patch_default_backend.return_value
    )
    assert isinstance(signer, Signer)
    assert signer.algorithm is _algorithm
    assert signer.key is patch_serialization.load_pem_private_key.return_value


def test_GIVEN_unrecognized_encoding_WHEN_signer_from_key_bytes_THEN_raise_ValueError(
    patch_default_backend,
    patch_serialization,
    patch_build_hasher,
    patch_ec
):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    _algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)

    # Then: Raises ValueError
    with pytest.raises(ValueError):
        # When: from_key_bytes
        signer = Signer.from_key_bytes(
            algorithm=_algorithm,
            key_bytes=sentinel.key_bytes,
            # Given: Invalid encoding
            encoding="not an encoding"
        )


def test_signer_key_bytes(patch_default_backend, patch_serialization, patch_build_hasher, patch_ec):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)
    private_key = MagicMock()
    signer = Signer(algorithm, key=private_key)

    test = signer.key_bytes()

    assert test is private_key.private_bytes.return_value
    private_key.private_bytes.assert_called_once_with(
        encoding=patch_serialization.Encoding.DER,
        format=patch_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=patch_serialization.NoEncryption.return_value,
    )


def test_signer_encoded_public_key(
    patch_default_backend,
    patch_serialization,
    patch_build_hasher,
    patch_ecc_encode_compressed_point,
    patch_base64,
    patch_ec
):
    patch_ecc_encode_compressed_point.return_value = sentinel.compressed_point
    patch_base64.b64encode.return_value = sentinel.encoded_point
    private_key = MagicMock()

    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)

    signer = Signer(algorithm, key=private_key)
    test_key = signer.encoded_public_key()

    patch_ecc_encode_compressed_point.assert_called_once_with(private_key)
    patch_base64.b64encode.assert_called_once_with(sentinel.compressed_point)
    assert test_key == sentinel.encoded_point


def test_signer_update(patch_default_backend, patch_serialization, patch_build_hasher, patch_ec):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)
    signer = Signer(algorithm, key=MagicMock())
    signer.update(sentinel.data)
    patch_build_hasher.return_value.update.assert_called_once_with(sentinel.data)


def test_signer_finalize(
    patch_default_backend, patch_serialization, patch_build_hasher, patch_ecc_static_length_signature, patch_ec
):
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info, spec=patch_ec.EllipticCurve)
    algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)
    private_key = MagicMock()

    signer = Signer(algorithm, key=private_key)
    test_signature = signer.finalize()

    patch_build_hasher.return_value.finalize.assert_called_once_with()
    patch_ecc_static_length_signature.assert_called_once_with(
        key=private_key, algorithm=algorithm, digest=patch_build_hasher.return_value.finalize.return_value
    )
    assert test_signature is patch_ecc_static_length_signature.return_value
