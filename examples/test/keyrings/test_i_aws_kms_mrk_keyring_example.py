# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS MRK keyring example."""
import pytest

from ...src.keyrings.aws_kms_mrk_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS MRK Keyring example."""
    encrypt_kms_key_id = \
        "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    decrypt_kms_key_id = \
        "arn:aws:kms:eu-west-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    encrypt_and_decrypt_with_keyring(encrypt_kms_key_id, decrypt_kms_key_id)
