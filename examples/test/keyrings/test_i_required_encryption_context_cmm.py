# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the hierarchical keyring example."""
import pytest

from ...src.keyrings.required_encryption_context_cmm import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    key_arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    encrypt_and_decrypt_with_keyring(key_arn)
