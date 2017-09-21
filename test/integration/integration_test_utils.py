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
"""Utility functions to handle configuration, credentials setup, and test skip
decision making for integration tests."""
import os

from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

SKIP_MESSAGE = (
    'Required environment variables not found. Skipping integration tests.'
    ' See integration tests README.rst for more information.'
)
TEST_CONTROL = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL'
AWS_KMS_KEY_ID = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID'


def skip_tests():
    """Only run tests if both required environment variables are found."""
    for var in (TEST_CONTROL, AWS_KMS_KEY_ID):
        if os.environ.get(var, None) is None:
            return False
    return True


def get_cmk_arn():
    """Retrieves the target CMK ARN from environment variable."""
    return os.environ.get(AWS_KMS_KEY_ID)


def setup_kms_master_key_provider():
    """Reads the test_values config file and builds the requested KMS Master Key Provider."""
    cmk_arn = get_cmk_arn()
    kms_master_key_provider = KMSMasterKeyProvider()
    kms_master_key_provider.add_master_key(cmk_arn)
    return kms_master_key_provider
