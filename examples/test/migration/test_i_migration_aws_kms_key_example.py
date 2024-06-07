# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the migration_aws_kms_key_example."""
import pytest

from ...src.migration.migration_aws_kms_key_example import (
    migration_aws_kms_key,
)

pytestmark = [pytest.mark.examples]


def test_migration_aws_kms_key():
    """Test function for migrating using AWS KMS Keys."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    migration_aws_kms_key(kms_key_id)
