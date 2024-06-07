# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the migration_to_raw_aes_keyring_from_raw_aes_master_key_provider_example."""
import pytest

from ...src.migration.migration_raw_aes_key_example import (
    migration_to_raw_aes_keyring_from_raw_aes_master_key_provider,
)

pytestmark = [pytest.mark.examples]


def test_migration_to_raw_aes_keyring_from_raw_aes_master_key_provider():
    """Test function for migrating to Raw AES Keyring from Raw AES Master Key Provider."""
    migration_to_raw_aes_keyring_from_raw_aes_master_key_provider()
