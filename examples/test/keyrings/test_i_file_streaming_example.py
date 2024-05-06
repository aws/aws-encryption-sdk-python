# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the file streaming keyring example."""
import pytest

from ...src.keyrings.file_streaming_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt for file streaming example using Raw AES keyring."""
    plaintext_filename = "test_keyrings/my-secret-data.dat"
    ciphertext_filename = 'test_keyrings/my-encrypted-data.ct'
    new_plaintext_filename = 'test_keyrings/my-decrypted-data.dat'
    encrypt_and_decrypt_with_keyring(plaintext_filename,
                                     ciphertext_filename,
                                     new_plaintext_filename)
