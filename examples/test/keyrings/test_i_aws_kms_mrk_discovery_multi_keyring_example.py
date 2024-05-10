# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS MRK Discovery Multi keyring example."""
import pytest

from ...src.keyrings.aws_kms_mrk_discovery_multi_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using AWS KMS MRK Discovery Multi Keyring example."""
    mrk_key_id_encrypt = \
        "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    mrk_encrypt_region = "us-east-1"
    aws_account_id = "658956600833"
    aws_regions = ["us-west-2", "us-east-1"]
    encrypt_and_decrypt_with_keyring(mrk_key_id_encrypt,
                                     mrk_encrypt_region,
                                     aws_account_id,
                                     aws_regions)
