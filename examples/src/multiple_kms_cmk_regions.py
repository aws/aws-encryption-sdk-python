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
"""
Example showing basic encryption and decryption of a value already in memory
using multiple KMS CMKs in multiple regions.
"""
import aws_encryption_sdk


def encrypt(kms_key_provider, source_plaintext):
    """Encrypts source_plaintext with the key(s) in kms_key_provider"""
    return aws_encryption_sdk.encrypt(source=source_plaintext, key_provider=kms_key_provider)


def decrypt(kms_key_provider, ciphertext):
    """Decrypts ciphertext with the key(s) in kms_key_provider"""
    return aws_encryption_sdk.decrypt(source=ciphertext, key_provider=kms_key_provider)


def multiple_kms_cmk_regions(key_arn1, key_arn2, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under multiple KMS customer master keys (CMKs) in multiple regions.

    :param str key_arn1: Amazon Resource Name (ARN) of the KMS CMK
    :param str key_arn2: Amazon Resource Name (ARN) of another KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    # Check that these keys are in different regions
    assert not key_arn1[12:21] == key_arn2[12:21]

    kwargs = dict(key_ids=[key_arn1, key_arn2])

    if botocore_session is not None:
        kwargs["botocore_session"] = botocore_session

    # Create master key provider using the ARN of the key and the session (botocore_session)
    kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, encrypted_message_header = encrypt(kms_key_provider, source_plaintext)

    # Check if both key ARNs are in the message headers
    assert len(encrypted_message_header.encrypted_data_keys) == 2

    # Decrypt the encrypted message using the AWS Encryption SDK. It returns the decrypted message and the header
    # Either of our keys can be used to decrypt the message
    plaintext1, decrypted_message_header1 = decrypt(
        aws_encryption_sdk.KMSMasterKeyProvider(**dict(key_ids=[key_arn1])), ciphertext
    )
    plaintext2, decrypted_message_header2 = decrypt(
        aws_encryption_sdk.KMSMasterKeyProvider(**dict(key_ids=[key_arn2])), ciphertext
    )

    # Check if the original message and the decrypted message are the same
    assert source_plaintext == plaintext1
    assert source_plaintext == plaintext2

    # Check if the headers of the encrypted message and decrypted message match
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header1.encryption_context.items()
    )
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header2.encryption_context.items()
    )
