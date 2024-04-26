# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS RSA keyring example."""
import pytest

from ...src.keyrings.aws_kms_rsa_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS RSA Keyring example."""
    kms_rsa_key_id = "arn:aws:kms:us-west-2:370957321024:key/mrk-63d386cb70614ea59b32ad65c9315297"
    encrypt_and_decrypt_with_keyring(kms_rsa_key_id)
