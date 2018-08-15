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
"""Unit test suite for ``aws_encryption_sdk.internal.crypto.elliptic_curve``."""
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.utils import InterfaceNotImplemented
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.internal.crypto.elliptic_curve
from aws_encryption_sdk.exceptions import NotSupportedError
from aws_encryption_sdk.internal.crypto.elliptic_curve import (
    _ECC_CURVE_PARAMETERS,
    _ecc_decode_compressed_point,
    _ecc_encode_compressed_point,
    _ecc_public_numbers_from_compressed_point,
    _ecc_static_length_signature,
    _ECCCurveParameters,
    generate_ecc_signing_key,
)

from .test_crypto import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_default_backend(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'default_backend')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.default_backend


@pytest.yield_fixture
def patch_ec(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'ec')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.ec


@pytest.yield_fixture
def patch_pow(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'pow')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.pow


@pytest.yield_fixture
def patch_encode_dss_signature(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'encode_dss_signature')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.encode_dss_signature


@pytest.yield_fixture
def patch_decode_dss_signature(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'decode_dss_signature')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.decode_dss_signature


@pytest.yield_fixture
def patch_ecc_decode_compressed_point(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, '_ecc_decode_compressed_point')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve._ecc_decode_compressed_point


@pytest.yield_fixture
def patch_verify_interface(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'verify_interface')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.verify_interface


@pytest.yield_fixture
def patch_ecc_curve_parameters(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, '_ECC_CURVE_PARAMETERS')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve._ECC_CURVE_PARAMETERS


@pytest.yield_fixture
def patch_prehashed(mocker):
    mocker.patch.object(aws_encryption_sdk.internal.crypto.elliptic_curve, 'Prehashed')
    yield aws_encryption_sdk.internal.crypto.elliptic_curve.Prehashed


def test_ecc_curve_not_in_cryptography():
    """If this test fails, then this pull or similar has gone through
        and this library should be updated to use the ECC curve
        parameters from cryptography.
        https://github.com/pyca/cryptography/pull/2499
    """
    assert not hasattr(ec.SECP384R1, 'a')


def test_ecc_curve_parameters_secp256r1():
    """Verify values from http://www.secg.org/sec2-v2.pdf"""
    p = pow(2, 224) * (pow(2, 32) - 1) + pow(2, 192) + pow(2, 96) - 1
    a = int((
        'FFFFFFFF' '00000001' '00000000' '00000000' '00000000' 'FFFFFFFF' 'FFFFFFFF'
        'FFFFFFFC'
    ), 16)
    b = int((
        '5AC635D8' 'AA3A93E7' 'B3EBBD55' '769886BC' '651D06B0' 'CC53B0F6' '3BCE3C3E'
        '27D2604B'
    ), 16)
    order = int((
        'FFFFFFFF' '00000000' 'FFFFFFFF' 'FFFFFFFF' 'BCE6FAAD' 'A7179E84' 'F3B9CAC2'
        'FC632551'
    ), 16)
    assert _ECC_CURVE_PARAMETERS['secp256r1'].p == p
    assert _ECC_CURVE_PARAMETERS['secp256r1'].a == a
    assert _ECC_CURVE_PARAMETERS['secp256r1'].b == b
    assert _ECC_CURVE_PARAMETERS['secp256r1'].order == order


def test_ecc_curve_parameters_secp384r1():
    """Verify values from http://www.secg.org/sec2-v2.pdf"""
    p = pow(2, 384) - pow(2, 128) - pow(2, 96) + pow(2, 32) - 1
    a = int((
        'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
        'FFFFFFFE' 'FFFFFFFF' '00000000' '00000000' 'FFFFFFFC'
    ), 16)
    b = int((
        'B3312FA7' 'E23EE7E4' '988E056B' 'E3F82D19' '181D9C6E' 'FE814112' '0314088F'
        '5013875A' 'C656398D' '8A2ED19D' '2A85C8ED' 'D3EC2AEF'
    ), 16)
    order = int((
        'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'C7634D81'
        'F4372DDF' '581A0DB2' '48B0A77A' 'ECEC196A' 'CCC52973'
    ), 16)
    assert _ECC_CURVE_PARAMETERS['secp384r1'].p == p
    assert _ECC_CURVE_PARAMETERS['secp384r1'].a == a
    assert _ECC_CURVE_PARAMETERS['secp384r1'].b == b
    assert _ECC_CURVE_PARAMETERS['secp384r1'].order == order


def test_ecc_curve_parameters_secp521r1():
    """Verify values from http://www.secg.org/sec2-v2.pdf"""
    p = pow(2, 521) - 1
    a = int((
        '01FF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
        'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
        'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFC'
    ), 16)
    b = int((
        '0051' '953EB961' '8E1C9A1F' '929A21A0' 'B68540EE' 'A2DA725B' '99B315F3'
        'B8B48991' '8EF109E1' '56193951' 'EC7E937B' '1652C0BD' '3BB1BF07' '3573DF88'
        '3D2C34F1' 'EF451FD4' '6B503F00'
    ), 16)
    order = int((
        '01FF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
        'FFFFFFFF' 'FFFFFFFA' '51868783' 'BF2F966B' '7FCC0148' 'F709A5D0' '3BB5C9B8'
        '899C47AE' 'BB6FB71E' '91386409'
    ), 16)
    assert _ECC_CURVE_PARAMETERS['secp521r1'].p == p
    assert _ECC_CURVE_PARAMETERS['secp521r1'].a == a
    assert _ECC_CURVE_PARAMETERS['secp521r1'].b == b
    assert _ECC_CURVE_PARAMETERS['secp521r1'].order == order


def test_ecc_static_length_signature_first_try(
        patch_default_backend,
        patch_ec,
        patch_encode_dss_signature,
        patch_decode_dss_signature,
        patch_prehashed
):
    algorithm = MagicMock(signature_len=55)
    private_key = MagicMock()
    private_key.sign.return_value = b'a' * 55
    test_signature = _ecc_static_length_signature(
        key=private_key,
        algorithm=algorithm,
        digest=sentinel.digest
    )
    patch_prehashed.assert_called_once_with(algorithm.signing_hash_type.return_value)
    patch_ec.ECDSA.assert_called_once_with(patch_prehashed.return_value)
    private_key.sign.assert_called_once_with(
        sentinel.digest,
        patch_ec.ECDSA.return_value
    )
    assert not patch_encode_dss_signature.called
    assert not patch_decode_dss_signature.called
    assert test_signature is private_key.sign.return_value


def test_ecc_static_length_signature_single_negation(
        patch_default_backend,
        patch_ec,
        patch_encode_dss_signature,
        patch_decode_dss_signature,
        patch_prehashed
):
    algorithm = MagicMock(signature_len=55)
    algorithm.signing_algorithm_info.name = 'secp256r1'
    private_key = MagicMock()
    private_key.sign.return_value = b'a'
    patch_decode_dss_signature.return_value = sentinel.r, 100
    patch_encode_dss_signature.return_value = 'a' * 55
    test_signature = _ecc_static_length_signature(
        key=private_key,
        algorithm=algorithm,
        digest=sentinel.digest
    )
    assert len(private_key.sign.mock_calls) == 1
    patch_decode_dss_signature.assert_called_once_with(b'a')
    patch_encode_dss_signature.assert_called_once_with(
        sentinel.r,
        _ECC_CURVE_PARAMETERS['secp256r1'].order - 100
    )
    assert test_signature is patch_encode_dss_signature.return_value


def test_ecc_static_length_signature_recalculate(
        patch_default_backend,
        patch_ec,
        patch_encode_dss_signature,
        patch_decode_dss_signature,
        patch_prehashed
):
    algorithm = MagicMock(signature_len=55)
    algorithm.signing_algorithm_info.name = 'secp256r1'
    private_key = MagicMock()
    private_key.sign.side_effect = (b'a', b'b' * 55)
    patch_decode_dss_signature.return_value = sentinel.r, 100
    patch_encode_dss_signature.return_value = 'a' * 100
    test_signature = _ecc_static_length_signature(
        key=private_key,
        algorithm=algorithm,
        digest=sentinel.digest
    )
    assert len(private_key.sign.mock_calls) == 2
    assert len(patch_decode_dss_signature.mock_calls) == 1
    assert len(patch_encode_dss_signature.mock_calls) == 1
    assert test_signature == b'b' * 55


def test_ecc_encode_compressed_point_prime():
    compressed_point = _ecc_encode_compressed_point(
        private_key=VALUES['ecc_private_key_prime']
    )
    assert compressed_point == VALUES['ecc_compressed_point']


def test_ecc_encode_compressed_point_characteristic_two():
    with pytest.raises(NotSupportedError) as excinfo:
        _ecc_encode_compressed_point(VALUES['ecc_private_key_char2'])

    excinfo.match(r'Non-prime curves are not supported at this time')


def test_ecc_decode_compressed_point_infinity():
    with pytest.raises(NotSupportedError) as excinfo:
        _ecc_decode_compressed_point(
            curve=ec.SECP384R1(),
            compressed_point=b''
        )

    excinfo.match(r'Points at infinity are not allowed')


def test_ecc_decode_compressed_point_prime():
    x, y = _ecc_decode_compressed_point(
        curve=ec.SECP384R1(),
        compressed_point=VALUES['ecc_compressed_point']
    )
    numbers = VALUES['ecc_private_key_prime'].public_key().public_numbers()
    assert x == numbers.x
    assert y == numbers.y


@pytest.mark.skipif(
    sys.version_info.major == 3 and sys.version_info.minor == 4,
    reason='Patching builtin "pow" fails in Python3.4'
)
def test_ecc_decode_compressed_point_prime_characteristic_two(patch_pow):
    patch_pow.return_value = 1
    _, y = _ecc_decode_compressed_point(
        curve=ec.SECP384R1(),
        compressed_point=VALUES['ecc_compressed_point']
    )
    assert y == 1


@pytest.mark.skipif(
    sys.version_info.major == 3 and sys.version_info.minor == 4,
    reason='Patching builtin "pow" fails in Python3.4'
)
def test_ecc_decode_compressed_point_prime_not_characteristic_two(patch_pow):
    patch_pow.return_value = 0
    _, y = _ecc_decode_compressed_point(
        curve=ec.SECP384R1(),
        compressed_point=VALUES['ecc_compressed_point']
    )
    assert y == _ECC_CURVE_PARAMETERS['secp384r1'].p


def test_ecc_decode_compressed_point_prime_unsupported():
    with pytest.raises(NotSupportedError) as excinfo:
        _ecc_decode_compressed_point(
            curve=ec.SECP192R1(),
            compressed_point='\x02skdgaiuhgijudflkjsdgfkjsdflgjhsd'
        )

    excinfo.match(r'Curve secp192r1 is not supported at this time')


def test_ecc_decode_compressed_point_prime_complex(patch_ecc_curve_parameters):
    patch_ecc_curve_parameters.__getitem__.return_value = _ECCCurveParameters(
        p=5,
        a=5,
        b=5,
        order=5
    )
    mock_curve = MagicMock()
    mock_curve.name = 'secp_mock_curve'
    with pytest.raises(NotSupportedError) as excinfo:
        _ecc_decode_compressed_point(
            curve=mock_curve,
            compressed_point=VALUES['ecc_compressed_point']
        )

    excinfo.match(r'S not 1 :: Curve not supported at this time')


def test_ecc_decode_compressed_point_nonprime_characteristic_two():
    with pytest.raises(NotSupportedError) as excinfo:
        _ecc_decode_compressed_point(
            curve=ec.SECT409K1(),
            compressed_point='\x02skdgaiuhgijudflkjsdgfkjsdflgjhsd'
        )

    excinfo.match(r'Non-prime curves are not supported at this time')


def test_ecc_public_numbers_from_compressed_point(patch_ec, patch_ecc_decode_compressed_point):
    patch_ecc_decode_compressed_point.return_value = sentinel.x, sentinel.y
    patch_ec.EllipticCurvePublicNumbers.return_value = sentinel.public_numbers_instance
    test = _ecc_public_numbers_from_compressed_point(
        curve=sentinel.curve_instance,
        compressed_point=sentinel.compressed_point
    )
    patch_ecc_decode_compressed_point.assert_called_once_with(sentinel.curve_instance, sentinel.compressed_point)
    patch_ec.EllipticCurvePublicNumbers.assert_called_once_with(
        x=sentinel.x,
        y=sentinel.y,
        curve=sentinel.curve_instance
    )
    assert test == sentinel.public_numbers_instance


def test_generate_ecc_signing_key_supported(patch_default_backend, patch_ec, patch_verify_interface):
    patch_ec.generate_private_key.return_value = sentinel.raw_signing_key
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info)
    mock_algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)

    test_signing_key = generate_ecc_signing_key(algorithm=mock_algorithm)

    patch_verify_interface.assert_called_once_with(
        patch_ec.EllipticCurve,
        mock_algorithm_info
    )
    patch_ec.generate_private_key.assert_called_once_with(
        curve=sentinel.algorithm_info,
        backend=patch_default_backend.return_value
    )
    assert test_signing_key is sentinel.raw_signing_key


def test_generate_ecc_signing_key_unsupported(patch_default_backend, patch_ec, patch_verify_interface):
    patch_verify_interface.side_effect = InterfaceNotImplemented
    mock_algorithm_info = MagicMock(return_value=sentinel.algorithm_info)
    mock_algorithm = MagicMock(signing_algorithm_info=mock_algorithm_info)

    with pytest.raises(NotSupportedError) as excinfo:
        generate_ecc_signing_key(algorithm=mock_algorithm)

    excinfo.match(r'Unsupported signing algorithm info')
    assert not patch_ec.generate_private_key.called
    assert not patch_default_backend.called
