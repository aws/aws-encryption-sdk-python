# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to use the streaming encrypt and decrypt APIs when working in memory.

For the purposes of this example, we demonstrate using AWS KMS,
but you can use other key management options with the AWS Encryption SDK.
Look in the ``keyring`` and ``master_key_provider`` directories
for examples that demonstrate how to use other key management configurations.
"""
import io

import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring


def run(aws_kms_cmk_arn, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using the streaming encrypt/decrypt APIs in-memory.

    :param str aws_kms_cmk_arn: AWS KMS CMK ARN to use to protect data keys
    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the keyring that determines how your keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk_arn)

    ciphertext = io.BytesIO()

    # The streaming API provides you with a context manager
    # that you can read from similar to how you would read from a file.
    with aws_encryption_sdk.stream(
        mode="encrypt", source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    ) as encryptor:
        # Iterate through the chunks in the context manager
        # and write the results to the ciphertext.
        for chunk in encryptor:
            ciphertext.write(chunk)

    assert ciphertext.getvalue() != source_plaintext

    # Reset the ciphertext stream position so that we can read from the beginning.
    ciphertext.seek(0)

    # Decrypt your encrypted data.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    decrypted = io.BytesIO()
    with aws_encryption_sdk.stream(mode="decrypt", source=ciphertext, keyring=keyring) as decryptor:
        # One benefit of using the streaming API is that
        # we can check the encryption context in the header before we start decrypting.
        #
        # Verify that the encryption context used in the decrypt operation matches what you expect.
        # The AWS Encryption SDK can add pairs, so don't require an exact match.
        #
        # In production, always use a meaningful encryption context.
        assert set(encryption_context.items()) <= set(decryptor.header.encryption_context.items())

        # Now that we are confident that the message is what we think it should be,
        # we can start decrypting.
        for chunk in decryptor:
            decrypted.write(chunk)

    # Verify that the "cycled" (encrypted then decrypted) plaintext
    # is identical to the original plaintext.
    assert decrypted.getvalue() == source_plaintext
