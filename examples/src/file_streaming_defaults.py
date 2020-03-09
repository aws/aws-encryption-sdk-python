# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to use the streaming encrypt and decrypt APIs when working with files.

For the purposes of this example, we demonstrate using AWS KMS,
but you can use other key management options with the AWS Encryption SDK.
Look in the ``keyring`` and ``master_key_provider`` directories
for examples that demonstrate how to use other key management configurations.
"""
import filecmp

import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring


def run(aws_kms_cmk, source_plaintext_filename):
    # type: (str, str) -> None
    """Demonstrate an encrypt/decrypt cycle using the streaming encrypt/decrypt APIs to work with files.

    :param str aws_kms_cmk: AWS KMS CMK ARN to use to protect data keys
    :param str source_plaintext_filename: Path to plaintext file to encrypt
    """
    # We assume that you can also write in the directory containing the plaintext file,
    # so that is where we will put all of the results.
    ciphertext_filename = source_plaintext_filename + ".encrypted"
    decrypted_filename = ciphertext_filename + ".decrypted"

    # Prepare your encryption context.
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the keyring that determines how your keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk)

    # Open the files you want to work with.
    with open(source_plaintext_filename, "rb") as plaintext, open(ciphertext_filename, "wb") as ciphertext:
        # The streaming API provides you with a context manager
        # that you can read from similar to how you would read from a file.
        with aws_encryption_sdk.stream(
            mode="encrypt", source=plaintext, encryption_context=encryption_context, keyring=keyring
        ) as encryptor:
            # Iterate through the chunks in the context manager
            # and write the results to the ciphertext.
            for chunk in encryptor:
                ciphertext.write(chunk)

    # Verify that the ciphertext and plaintext are different.
    assert not filecmp.cmp(source_plaintext_filename, ciphertext_filename)

    # Open the files you want to work with.
    with open(ciphertext_filename, "rb") as ciphertext, open(decrypted_filename, "wb") as decrypted:
        # Decrypt your encrypted data.
        #
        # We do not need to specify the encryption context on decrypt
        # because the header message includes the encryption context.
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
    assert filecmp.cmp(source_plaintext_filename, decrypted_filename)
