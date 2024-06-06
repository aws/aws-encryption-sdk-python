# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the migration_to_aws_kms_keyring_from_aws_kms_master_key_provider_example."""
import pytest

from ...src.migration.migration_to_aws_kms_keyring_from_aws_kms_master_key_provider_example import (
    migration_to_aws_kms_keyring_from_aws_kms_master_key_provider,
)

pytestmark = [pytest.mark.examples]


def test_migration_to_aws_kms_keyring_from_aws_kms_master_key_provider():
    """Test function for migrating to AWS KMS Keyring from AWS KMS Master Key Provider."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    migration_to_aws_kms_keyring_from_aws_kms_master_key_provider(kms_key_id)
