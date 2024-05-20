# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions to handle configuration and credentials setup for integration tests."""
import os

import botocore.session

from aws_encryption_sdk.key_providers.kms import StrictAwsKmsMasterKeyProvider

AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"
AWS_KMS_KEY_ID_2 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2"
AWS_KMS_MRK_KEY_ID_1 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_1"
AWS_KMS_MRK_KEY_ID_2 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_2"
_KMS_MKP = None
_KMS_MKP_BOTO = None


def _get_single_cmk_arn(name):
    # type: (str) -> str
    """Retrieve a single target AWS KMS CMK ARN from the specified environment variable name."""
    arn = os.environ.get(name, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(name)
        )
    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn
    raise ValueError("KMS CMK ARN provided for integration tests much be a key not an alias")


def get_cmk_arn():
    """Retrieves the target AWS KMS CMK ARN from environment variable."""
    return _get_single_cmk_arn(AWS_KMS_KEY_ID)


def get_second_cmk_arn():
    """Retrieves the target AWS KMS CMK ARN from environment variable."""
    return _get_single_cmk_arn(AWS_KMS_KEY_ID_2)


def get_mrk_arn():
    """Retrieves the target AWS KMS CMK ARN from environment variable."""
    return _get_single_cmk_arn(AWS_KMS_MRK_KEY_ID_1)


def get_second_mrk_arn():
    """Retrieves the target AWS KMS CMK ARN from environment variable."""
    return _get_single_cmk_arn(AWS_KMS_MRK_KEY_ID_2)


def setup_kms_master_key_provider(cache=True):
    """Reads the test_values config file and builds the requested KMS Master Key Provider."""
    global _KMS_MKP  # pylint: disable=global-statement
    if cache and _KMS_MKP is not None:
        return _KMS_MKP

    cmk_arn = get_cmk_arn()
    kms_master_key_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

    if cache:
        _KMS_MKP = kms_master_key_provider

    return kms_master_key_provider


def setup_kms_master_key_provider_with_botocore_session(cache=True):
    """Reads the test_values config file and builds the requested KMS Master Key Provider with botocore_session."""
    global _KMS_MKP_BOTO  # pylint: disable=global-statement
    if cache and _KMS_MKP_BOTO is not None:
        return _KMS_MKP_BOTO

    cmk_arn = get_cmk_arn()
    kms_master_key_provider = StrictAwsKmsMasterKeyProvider(
        key_ids=[cmk_arn], botocore_session=botocore.session.Session()
    )

    if cache:
        _KMS_MKP_BOTO = kms_master_key_provider

    return kms_master_key_provider


def setup_kms_master_key_provider_with_duplicate_keys(num_keys):
    """Reads the test_values config file and builds the requested KMS Master Key Provider with multiple copies of
    the requested key."""
    assert num_keys > 1
    cmk_arn = get_cmk_arn()
    provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])
    for _ in range(num_keys - 1):
        provider.add_master_key_provider(StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn]))
    return provider
