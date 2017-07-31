"""Unit test suite for aws_encryption_sdk.identifiers"""
import pytest

from aws_encryption_sdk.exceptions import InvalidAlgorithmError
from aws_encryption_sdk.identifiers import _kdf_input_len_check, Algorithm


@pytest.mark.parametrize('check_algorithm, safe_to_cache', (
    (Algorithm.AES_128_GCM_IV12_TAG16, False),
    (Algorithm.AES_192_GCM_IV12_TAG16, False),
    (Algorithm.AES_256_GCM_IV12_TAG16, False),
    (Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256, True),
    (Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256, True),
    (Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256, True),
    (Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, True),
    (Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, True),
    (Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, True)
))
def test_algorithm_safe_to_cache(check_algorithm, safe_to_cache):
    if safe_to_cache:
        assert check_algorithm.safe_to_cache()
    else:
        assert not check_algorithm.safe_to_cache()


def test_kdf_input_len_check_valid():
    _kdf_input_len_check(
        data_key_len=5,
        kdf_type=5,
        kdf_input_len=5
    )


def test_kdf_input_len_check_invalid_no_kdf():
    with pytest.raises(InvalidAlgorithmError) as excinfo:
        _kdf_input_len_check(data_key_len=2, kdf_type=None, kdf_input_len=5)

    excinfo.match(r'Invalid Algorithm definition: data_key_len must equal kdf_input_len for non-KDF algorithms')


def test_kdf_input_len_check_invalid_with_kdf():
    with pytest.raises(InvalidAlgorithmError) as excinfo:
        _kdf_input_len_check(data_key_len=5, kdf_type=5, kdf_input_len=2)

    excinfo.match(r'Invalid Algorithm definition: data_key_len must not be greater than kdf_input_len')
