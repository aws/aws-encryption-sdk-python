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
import pytest

from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring

AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"
AWS_KMS_KEY_ID_2 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2"
_KMS_MKP = None
_KMS_MKP_BOTO = None
_KMS_KEYRING = None


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


def get_all_cmk_arns():
    """Retrieve all known target AWS KMS CMK ARNs from environment variables."""
    return [_get_single_cmk_arn(AWS_KMS_KEY_ID), _get_single_cmk_arn(AWS_KMS_KEY_ID_2)]


def setup_kms_master_key_provider(cache=True):
    """Build an AWS KMS Master Key Provider."""
    global _KMS_MKP  # pylint: disable=global-statement
    if cache and _KMS_MKP is not None:
        return _KMS_MKP

    cmk_arn = get_cmk_arn()
    kms_master_key_provider = KMSMasterKeyProvider()
    kms_master_key_provider.add_master_key(cmk_arn.encode("utf-8"))

    if cache:
        _KMS_MKP = kms_master_key_provider

    return kms_master_key_provider


def setup_kms_master_key_provider_with_botocore_session(cache=True):
    """Build an AWS KMS Master Key Provider with an explicit botocore_session."""
    global _KMS_MKP_BOTO  # pylint: disable=global-statement
    if cache and _KMS_MKP_BOTO is not None:
        return _KMS_MKP_BOTO

    cmk_arn = get_cmk_arn()
    kms_master_key_provider = KMSMasterKeyProvider(botocore_session=botocore.session.Session())
    kms_master_key_provider.add_master_key(cmk_arn.encode("utf-8"))

    if cache:
        _KMS_MKP_BOTO = kms_master_key_provider

    return kms_master_key_provider


def build_aws_kms_keyring(generate=True, cache=True):
    """Build an AWS KMS keyring."""
    global _KMS_KEYRING  # pylint: disable=global-statement
    if cache and _KMS_KEYRING is not None:
        return _KMS_KEYRING

    cmk_arn = get_cmk_arn()

    if generate:
        kwargs = dict(generator_key_id=cmk_arn)
    else:
        kwargs = dict(key_ids=[cmk_arn])

    keyring = KmsKeyring(**kwargs)

    if cache:
        _KMS_KEYRING = keyring

    return keyring


@pytest.fixture
def aws_kms_keyring():
    return build_aws_kms_keyring()
