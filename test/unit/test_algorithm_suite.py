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
"""Unit test suite for aws_encryption_sdk.identifiers.AlgorithmSuite."""
import pytest

from aws_encryption_sdk.identifiers import AlgorithmSuite


@pytest.mark.parametrize(
    "suite",
    (
        AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    ),
)
def test_committing_suites_properties(suite):
    assert suite.is_committing()
    assert suite.message_format_version == 0x02
    assert suite.message_id_length() == 32


@pytest.mark.parametrize(
    "suite",
    (
        AlgorithmSuite.AES_128_GCM_IV12_TAG16,
        AlgorithmSuite.AES_192_GCM_IV12_TAG16,
        AlgorithmSuite.AES_256_GCM_IV12_TAG16,
        AlgorithmSuite.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
        AlgorithmSuite.AES_192_GCM_IV12_TAG16_HKDF_SHA256,
        AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
        AlgorithmSuite.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        AlgorithmSuite.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    ),
)
def test_noncommitting_suites_properties(suite):
    assert not suite.is_committing()
    assert suite.message_format_version == 0x01
    assert suite.message_id_length() == 16
