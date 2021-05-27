# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Example showing basic encryption and decryption of streaming data in memory using one KMS CMK."""
import filecmp

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy


def encrypt_decrypt_stream(key_arn, source_plaintext_filename, botocore_session=None):
    """Encrypts and then decrypts streaming data under one KMS customer master key (CMK).

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    :param str source_plaintext_filename: Filename of file to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    kwargs = dict()

    kwargs["key_ids"] = [key_arn]

    if botocore_session is not None:
        kwargs["botocore_session"] = botocore_session

    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Create master key provider using the ARN of the key and the session (botocore_session)
    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kwargs)

    ciphertext_filename = source_plaintext_filename + ".encrypted"
    decrypted_text_filename = source_plaintext_filename + ".decrypted"

    # Encrypt the plaintext using the AWS Encryption SDK.
    with open(source_plaintext_filename, "rb") as plaintext, open(ciphertext_filename, "wb") as ciphertext:
        with client.stream(source=plaintext, mode="e", key_provider=kms_key_provider) as encryptor:
            for chunk in encryptor:
                ciphertext.write(chunk)

    # Decrypt the encrypted message using the AWS Encryption SDK.
    # Buffer the data in memory before writing to disk to ensure the signature is verified first.
    with open(ciphertext_filename, "rb") as ciphertext, open(decrypted_text_filename, "wb") as plaintext:
        with client.stream(source=ciphertext, mode="d", key_provider=kms_key_provider) as decryptor:
            plaintext.write(decryptor.read())

    # Check if the original message and the decrypted message are the same
    assert filecmp.cmp(source_plaintext_filename, decrypted_text_filename)

    # Check if the headers of the encrypted message and decrypted message match
    assert all(
        pair in encryptor.header.encryption_context.items() for pair in decryptor.header.encryption_context.items()
    )
    return ciphertext_filename, decrypted_text_filename
