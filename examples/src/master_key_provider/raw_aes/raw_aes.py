# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example is intended to serve as reference material for users migrating away from master key providers.
We recommend using keyrings rather than master key providers.
For examples using keyrings, see the ``examples/src/keyrings`` directory.

This examples shows how to configure and use a raw AES master key.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider

In this example, we use the one-step encrypt and decrypt APIs.
"""
import os

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.key_providers.raw import RawMasterKey, WrappingKey


def run(source_plaintext):
    # type: (bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a raw AES master key.

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

    # Choose the wrapping algorithm for your master key to use.
    wrapping_algorithm = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING

    # Generate an AES key to use with your master key.
    # The key size depends on the wrapping algorithm.
    #
    # In practice, you should get this key from a secure key management system such as an HSM.
    key = os.urandom(wrapping_algorithm.algorithm.kdf_input_len)

    # Create the master key that determines how your data keys are protected.
    master_key = RawMasterKey(
        # The provider ID and key ID are defined by you
        # and are used by the raw AES master key
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        provider_id="some managed raw keys",  # provider ID corresponds to key namespace for keyrings
        key_id=b"my AES wrapping key",  # key ID corresponds to key name for keyrings
        wrapping_key=WrappingKey(
            wrapping_algorithm=wrapping_algorithm, wrapping_key_type=EncryptionKeyType.SYMMETRIC, wrapping_key=key,
        ),
    )

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, key_provider=master_key
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same master key you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=master_key)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
