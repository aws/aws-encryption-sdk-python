# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This examples shows how to configure and use a raw AES keyring.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-aes-keyring

In this example, we use the one-step encrypt and decrypt APIs.
"""
import os

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyrings.raw import RawAESKeyring


def run(source_plaintext):
    # type: (bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a raw AES keyring.

    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Choose the wrapping algorithm for the keyring to use.
    wrapping_algorithm = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING

    # Generate an AES key to use with your keyring.
    # The key size depends on the wrapping algorithm.
    #
    # In practice, you should get this key from a secure key management system such as an HSM.
    key = os.urandom(wrapping_algorithm.algorithm.kdf_input_len)

    # Create the keyring that determines how your data keys are protected.
    keyring = RawAESKeyring(
        # The key namespace and key name are defined by you
        # and are used by the raw RSA keyring
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        #
        # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-aes-keyring
        key_namespace="some managed raw keys",
        key_name=b"my AES wrapping key",
        wrapping_key=key,
        wrapping_algorithm=wrapping_algorithm,
    )

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same keyring you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
