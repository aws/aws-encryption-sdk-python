# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS MRK keyring example."""
import pytest

from ..src.aws_kms_mrk_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS MRK Keyring example."""
    mrk_key_id_encrypt = \
        "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    mrk_replica_key_id_decrypt = \
        "arn:aws:kms:eu-west-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    mrk_encrypt_region = "us-east-1"
    mrk_replica_decrypt_region = "eu-west-1"
    encrypt_and_decrypt_with_keyring(mrk_key_id_encrypt,
                                     mrk_replica_key_id_decrypt,
                                     mrk_encrypt_region,
                                     mrk_replica_decrypt_region)
