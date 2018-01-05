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
"""Unit test suite for aws_encryption_sdk.identifiers"""
from mock import Mock
import pytest

from aws_encryption_sdk.exceptions import InvalidAlgorithmError
from aws_encryption_sdk.identifiers import Algorithm, EncryptionSuite, KDFSuite


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


@pytest.mark.parametrize('suite', [suite for suite in EncryptionSuite])
def test_encryption_suite_invalid_kdf(suite):
    mock_kdf = Mock()
    mock_kdf.input_length.return_value = 1
    with pytest.raises(InvalidAlgorithmError) as excinfo:
        suite.valid_kdf(mock_kdf)

    excinfo.match(r'Invalid Algorithm definition: data_key_len must not be greater than kdf_input_len')


def build_valid_kdf_checks():
    checks = []
    for suite in EncryptionSuite:
        checks.append((suite, KDFSuite.NONE, True))
        checks.append((suite, KDFSuite.HKDF_SHA256, True))
        checks.append((suite, KDFSuite.HKDF_SHA384, True))
    return checks


@pytest.mark.parametrize('encryption, kdf, expected', build_valid_kdf_checks())
def test_encryption_suite_valid_kdf(encryption, kdf, expected):
    actual = encryption.valid_kdf(kdf)

    if expected:
        assert actual
    else:
        assert not actual
