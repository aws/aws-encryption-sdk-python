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
"""Utility functions to handle configuration and credentials setup for integration tests."""
import os

import botocore.session

from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"
AWS_KMS_KEY_ID_2 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2"
_KMS_MKP = None
_KMS_MKP_BOTO = None


def get_cmk_arn():
    """Retrieves the target CMK ARN from environment variable."""
    arn = os.environ.get(AWS_KMS_KEY_ID, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID
            )
        )
    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn
    raise ValueError("KMS CMK ARN provided for integration tests much be a key not an alias")

def get_cmk_arn(region_name):
    """Retrieves a CMK ARN based on the requested region_name"""
    if AWS_KMS_KEY_ID in os.environ and AWS_KMS_KEY_ID_2 in os.environ:
        raise ValueError(
            'Environment variable "{}" or "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID, AWS_KMS_KEY_ID_2
            )
        )
    arn_1 = os.environ.get(AWS_KMS_KEY_ID, None)
    arn_2 = os.environ.get(AWS_KMS_KEY_ID_2, None)
    if arn_1.split(':')[3] == region_name:
        return arn_1
    elif arn_2.split(':')[3] == region_name:
        return arn_2
    else:
        raise ValueError(
            'No CMK in the region {} exist in either of your environment variables "{}" or "{}"'.format(
                region_name, AWS_KMS_KEY_ID, AWS_KMS_KEY_ID_2
            )
        )

def setup_kms_master_key_provider(cache=True):
    """Reads the test_values config file and builds the requested KMS Master Key Provider."""
    global _KMS_MKP  # pylint: disable=global-statement
    if cache and _KMS_MKP is not None:
        return _KMS_MKP

    cmk_arn = get_cmk_arn()
    kms_master_key_provider = KMSMasterKeyProvider()
    kms_master_key_provider.add_master_key(cmk_arn)

    if cache:
        _KMS_MKP = kms_master_key_provider

    return kms_master_key_provider


def setup_kms_master_key_provider_with_botocore_session(cache=True):
    """Reads the test_values config file and builds the requested KMS Master Key Provider with botocore_session."""
    global _KMS_MKP_BOTO  # pylint: disable=global-statement
    if cache and _KMS_MKP_BOTO is not None:
        return _KMS_MKP_BOTO

    cmk_arn = get_cmk_arn()
    kms_master_key_provider = KMSMasterKeyProvider(botocore_session=botocore.session.Session())
    kms_master_key_provider.add_master_key(cmk_arn)

    if cache:
        _KMS_MKP_BOTO = kms_master_key_provider

    return kms_master_key_provider
