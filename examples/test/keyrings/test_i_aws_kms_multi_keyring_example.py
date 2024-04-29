# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS multi keyring example."""
import pytest

from ...src.keyrings.aws_kms_multi_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS Multi Keyring example."""
    default_region_kms_key_id = \
        "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    second_region_kms_key_id = \
        "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2"
    encrypt_and_decrypt_with_keyring(default_region_kms_key_id, second_region_kms_key_id)
