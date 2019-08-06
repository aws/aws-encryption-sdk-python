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
"""Example showing basic encryption and decryption of a value already in memory
using one KMS CMK with an unsigned algorithm.
"""
import aws_encryption_sdk
from aws_encryption_sdk import encrypt, decrypt
from aws_encryption_sdk.identifiers import Algorithm


def encrypt_decrypt(key_arn, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under one KMS customer master key (CMK) with an unsigned algorithm.

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    kwargs = dict(key_ids=[key_arn])

    if botocore_session is not None:
        kwargs["botocore_session"] = botocore_session

    # Create master key provider using the ARN of the key and the session (botocore_session)
    kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, encrypted_message_header = encrypt(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256, source=source_plaintext, key_provider=kms_key_provider
    )

    # Decrypt the encrypted message using the AWS Encryption SDK. It returns the decrypted message and the header
    plaintext, decrypted_message_header = decrypt(source=ciphertext, key_provider=kms_key_provider)

    # Check if the original message and the decrypted message are the same
    assert source_plaintext == plaintext

    # Check if the headers of the encrypted message and decrypted message match
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header.encryption_context.items()
    )
