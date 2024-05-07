# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the migration_set_commitment_policy_example."""
import pytest

from ..src.migration_set_commitment_policy_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for setting commitment policy using the AWS KMS Keyring example."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    encrypt_and_decrypt_with_keyring(kms_key_id)
