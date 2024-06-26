# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Raw RSA keyring example with multi-threading."""
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ...src.multithreading import encrypt_and_decrypt_with_keyring
from ...src.multithreading.raw_rsa_keyring import create_keyring, generate_rsa_keys

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring(n_threads=10):
    """Test function for multi-threaded encrypt and decrypt using the Raw RSA Keyring example."""
    public_key, private_key = generate_rsa_keys()
    keyring = create_keyring(public_key=public_key, private_key=private_key)
    plaintext_data = b"Hello World"
    esdk_client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        thread_futures = {executor.submit(encrypt_and_decrypt_with_keyring,
                                          plaintext_data=plaintext_data,
                                          keyring=keyring,
                                          esdk_client=esdk_client): i for i in range(n_threads)}

        for future in as_completed(thread_futures):
            decrypted_plaintext_data = future.result()
            assert decrypted_plaintext_data == plaintext_data, \
                "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
