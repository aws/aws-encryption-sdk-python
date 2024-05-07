# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Set Encryption Algorithm Suite example for a Raw AES keyring."""
import pytest

from ...src.keyrings.set_encryption_algorithm_suite_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for setting an encryption algorithm suite in a Raw AES Keyring."""
    encrypt_and_decrypt_with_keyring()
