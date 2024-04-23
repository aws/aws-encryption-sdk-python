# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Raw AES keyring example."""
import pytest

from ...src.keyrings.raw_rsa_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using the Raw AES Keyring example."""
    encrypt_and_decrypt_with_keyring()
