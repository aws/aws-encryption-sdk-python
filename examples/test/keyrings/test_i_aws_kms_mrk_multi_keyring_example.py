# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS MRK Multi keyring example."""
import pytest

from ...src.keyrings.aws_kms_mrk_multi_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS MRK Multi Keyring example."""
    mrk_key_id = \
        "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    kms_key_id = \
        "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    mrk_replica_key_id = \
        "arn:aws:kms:eu-west-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    second_region = "eu-west-1"
    encrypt_and_decrypt_with_keyring(mrk_key_id, kms_key_id, mrk_replica_key_id, second_region)
