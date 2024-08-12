# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""init file for multi-threading examples."""
import time

from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk


def encrypt_and_decrypt_with_keyring(
    plaintext_data: bytes,
    keyring: IKeyring,
    client: aws_encryption_sdk.EncryptionSDKClient
):
    """Demonstrate how to encrypt and decrypt plaintext data using a keyring.

    Usage: encrypt_and_decrypt_with_keyring(plaintext_data, keyring, client)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param keyring: Keyring to use for encryption.
    :type keyring: IKeyring
    :param client: The Encryption SDK client to use for encryption.
    :type client: aws_encryption_sdk.EncryptionSDKClient
    :return: encrypted and decrypted (cycled) plaintext data
    :rtype: bytes
    """
    encryption_context: Dict[str, str] = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    ciphertext_data, _ = client.encrypt(
        source=plaintext_data,
        keyring=keyring,
        encryption_context=encryption_context
    )

    decrypted_plaintext_data, _ = client.decrypt(
        source=ciphertext_data,
        keyring=keyring,
        # Verify that the encryption context in the result contains the
        # encryption context supplied to the encrypt method
        encryption_context=encryption_context,
    )

    return decrypted_plaintext_data


def run_encrypt_and_decrypt_with_keyring_for_duration_seconds(
    plaintext_data: bytes,
    keyring: IKeyring,
    client: aws_encryption_sdk.EncryptionSDKClient,
    duration: int = 2
):
    """Helper function to repeatedly run an encrypt and decrypt cycle for 'duration' seconds."""
    time_end = time.time() + duration

    while time.time() < time_end:
        decrypted_plaintext_data = encrypt_and_decrypt_with_keyring(plaintext_data, keyring, client)
        assert decrypted_plaintext_data == plaintext_data, \
            "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
