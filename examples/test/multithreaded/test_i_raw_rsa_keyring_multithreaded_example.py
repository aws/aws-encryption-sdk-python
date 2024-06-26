# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Raw RSA keyring example with multi-threading."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest

from ...src.raw_rsa_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring(n_threads=10):
    """Test function for multi-threaded encrypt and decrypt using the Raw RSA Keyring example."""
    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        thread_futures = {executor.submit(encrypt_and_decrypt_with_keyring): i for i in range(n_threads)}

        for future in as_completed(thread_futures):
            thread_id = thread_futures[future]
            try:
                result = future.result()
                print(f"Thread {thread_id} passed with result: {result}")
            except Exception as e:
                raise e
