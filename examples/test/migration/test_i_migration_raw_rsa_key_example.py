# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the migration_raw_rsa_key_example."""
import pytest

from ...src.migration.migration_raw_rsa_key_example import migration_raw_rsa_key

pytestmark = [pytest.mark.examples]


def test_migration_raw_rsa_key():
    """Test function for migration of Raw RSA keys."""
    migration_raw_rsa_key()
