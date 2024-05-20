# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS KMS RSA keyring example."""
import pytest

from ..src.aws_kms_rsa_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the AWS KMS RSA Keyring example."""
    kms_rsa_key_id = "arn:aws:kms:us-west-2:370957321024:key/mrk-63d386cb70614ea59b32ad65c9315297"

    # THIS IS A PUBLIC RESOURCE AND SHOULD NOT BE USED IN A PRODUCTION ENVIRONMENT
    public_key = bytes("-----BEGIN PUBLIC KEY-----\n"
                       + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA27Uc/fBaMVhxCE/SpCMQ"
                       + "oSBRSzQJw+o2hBaA+FiPGtiJ/aPy7sn18aCkelaSj4kwoC79b/arNHlkjc7OJFsN"
                       + "/GoFKgNvaiY4lOeJqEiWQGSSgHtsJLdbO2u4OOSxh8qIRAMKbMgQDVX4FR/PLKeK"
                       + "fc2aCDvcNSpAM++8NlNmv7+xQBJydr5ce91eISbHkFRkK3/bAM+1iddupoRw4Wo2"
                       + "r3avzrg5xBHmzR7u1FTab22Op3Hgb2dBLZH43wNKAceVwKqKA8UNAxashFON7xK9"
                       + "yy4kfOL0Z/nhxRKe4jRZ/5v508qIzgzCksYy7Y3QbMejAtiYnr7s5/d5KWw0swou"
                       + "twIDAQAB"
                       + "\n-----END PUBLIC KEY-----", 'utf-8')
    encrypt_and_decrypt_with_keyring(kms_rsa_key_id, public_key)
