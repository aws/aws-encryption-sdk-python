# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to use the streaming encrypt and decrypt APIs on data in memory.

One benefit of using the streaming API is that
we can check the encryption context in the header before we start decrypting.

In this example, we use an AWS KMS customer master key (CMK),
but you can use other key management options with the AWS Encryption SDK.
For examples that demonstrate how to use other key management configurations,
see the ``keyring`` and ``mater_key_provider`` directories.
"""
import io

import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using the streaming encrypt/decrypt APIs in-memory.

    :param str aws_kms_cmk: The ARN of an AWS KMS CMK that protects data keys
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

    # Create the keyring that determines how your data keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk)

    ciphertext = io.BytesIO()

    # The streaming API provides a context manager.
    # You can read from it just as you read from a file.
    with aws_encryption_sdk.stream(
        mode="encrypt", source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    ) as encryptor:
        # Iterate through the segments in the context manager
        # and write the results to the ciphertext.
        for segment in encryptor:
            ciphertext.write(segment)

    # Verify that the ciphertext and plaintext are different.
    assert ciphertext.getvalue() != source_plaintext

    # Reset the ciphertext stream position so that we can read from the beginning.
    ciphertext.seek(0)

    # Decrypt your encrypted data.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    decrypted = io.BytesIO()
    with aws_encryption_sdk.stream(mode="decrypt", source=ciphertext, keyring=keyring) as decryptor:
        # Check the encryption context in the header before we start decrypting.
        #
        # Verify that the encryption context used in the decrypt operation includes
        # the encryption context that you specified when encrypting.
        # The AWS Encryption SDK can add pairs, so don't require an exact match.
        #
        # In production, always use a meaningful encryption context.
        assert set(encryption_context.items()) <= set(decryptor.header.encryption_context.items())

        # Now that we are more confident that we will decrypt the right message,
        # we can start decrypting.
        for segment in decryptor:
            decrypted.write(segment)

    # Verify that the decrypted plaintext is identical to the original plaintext.
    assert decrypted.getvalue() == source_plaintext
