# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS Discovery Multi keyring example."""
import pytest

from ..src.aws_kms_discovery_multi_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS Discovery Multi Keyring example."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    aws_account_id = "658956600833"
    aws_regions = ["us-east-1", "us-west-2"]
    encrypt_and_decrypt_with_keyring(kms_key_id, aws_account_id, aws_regions)
