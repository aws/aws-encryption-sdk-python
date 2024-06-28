# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Raw RSA keyring example with multi-threading."""
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from ...src.multithreading import run_encrypt_and_decrypt_with_keyring_for_duration_seconds
from ...src.multithreading.raw_rsa_keyring import create_keyring, generate_rsa_keys

pytestmark = [pytest.mark.examples]


def encrypt_and_decrypt_with_keyring_multithreaded_helper(n_threads=64, duration=60):
    """Helper function for multi-threaded encrypt and decrypt using a keyring for fixed n_threads and duration."""
    public_key, private_key = generate_rsa_keys()
    keyring = create_keyring(public_key=public_key, private_key=private_key)
    plaintext_data = b"Hello World"
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        thread_futures = {executor.submit(run_encrypt_and_decrypt_with_keyring_for_duration_seconds,
                                          plaintext_data=plaintext_data,
                                          keyring=keyring,
                                          client=client,
                                          duration=duration): i for i in range(n_threads)}

        for future in as_completed(thread_futures):
            future.result()


def test_encrypt_and_decrypt_with_keyring_multithreaded(n_threads_list: list = [1, 4, 16, 64], duration_list: list = [2, 10, 60]):
    """Test function for multi-threaded encrypt and decrypt using a keyring for different n_threads and duration."""
    for n in n_threads_list:
        for d in duration_list:
            encrypt_and_decrypt_with_keyring_multithreaded_helper(n_threads=n, duration=d)
