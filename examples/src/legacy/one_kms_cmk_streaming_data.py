# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example showing basic encryption and decryption of streaming data in memory using one AWS KMS CMK."""
import filecmp

import aws_encryption_sdk


def run(aws_kms_cmk, source_plaintext_filename, botocore_session=None):
    """Encrypts and then decrypts streaming data under one AWS KMS customer master key (CMK).

    :param str aws_kms_cmk: Amazon Resource Name (ARN) of the AWS KMS CMK
    :param str source_plaintext_filename: Filename of file to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    kwargs = dict()

    kwargs["key_ids"] = [aws_kms_cmk]

    if botocore_session is not None:
        kwargs["botocore_session"] = botocore_session

    # Create master key provider using the ARN of the key and the session (botocore_session)
    kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kwargs)

    ciphertext_filename = source_plaintext_filename + ".encrypted"
    decrypted_text_filename = source_plaintext_filename + ".decrypted"

    # Encrypt the plaintext using the AWS Encryption SDK.
    with open(source_plaintext_filename, "rb") as plaintext, open(ciphertext_filename, "wb") as ciphertext:
        with aws_encryption_sdk.stream(source=plaintext, mode="e", key_provider=kms_key_provider) as encryptor:
            for chunk in encryptor:
                ciphertext.write(chunk)

    # Decrypt the encrypted message using the AWS Encryption SDK.
    with open(ciphertext_filename, "rb") as ciphertext, open(decrypted_text_filename, "wb") as plaintext:
        with aws_encryption_sdk.stream(source=ciphertext, mode="d", key_provider=kms_key_provider) as decryptor:
            for chunk in decryptor:
                plaintext.write(chunk)

    # Check if the original message and the decrypted message are the same
    assert filecmp.cmp(source_plaintext_filename, decrypted_text_filename)

    # Check if the headers of the encrypted message and decrypted message match
    assert all(
        pair in encryptor.header.encryption_context.items() for pair in decryptor.header.encryption_context.items()
    )
    return ciphertext_filename, decrypted_text_filename
