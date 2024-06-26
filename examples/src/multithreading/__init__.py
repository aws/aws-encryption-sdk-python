# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""init file for multi-threading examples."""
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk


def encrypt_and_decrypt_with_keyring(
    plaintext_data: bytes,
    keyring: IKeyring,
    esdk_client: aws_encryption_sdk.EncryptionSDKClient
):
    """encrypt_and_decrypt_with_keyring how to encrypt plaintext data using a Raw AES keyring.

    Usage: encrypt_and_decrypt_with_keyring(plaintext_data, keyring, esdk_client)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param keyring: Keyring to use for encryption.
    :type keyring: IKeyring
    :param esdk_client: The Encryption SDK client to use for encryption.
    :type esdk_client: aws_encryption_sdk.EncryptionSDKClient
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

    ciphertext_data, _ = esdk_client.encrypt(
        source=plaintext_data,
        keyring=keyring,
        encryption_context=encryption_context
    )

    decrypted_plaintext_data, _ = esdk_client.decrypt(
        source=ciphertext_data,
        keyring=keyring
    )

    return decrypted_plaintext_data
