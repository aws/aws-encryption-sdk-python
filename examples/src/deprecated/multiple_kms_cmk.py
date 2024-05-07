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
"""Example showing basic encryption and decryption of a value already in memory using one KMS CMK."""
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy


def encrypt_decrypt(key_arns, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under two KMS customer master keys (CMK).

    :param str key_arns: Amazon Resource Names (ARNs) of the KMS CMKs
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    encrypt_kwargs = dict(key_ids=key_arns)

    if botocore_session is not None:
        encrypt_kwargs["botocore_session"] = botocore_session

    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Create strict master key provider that is only allowed to encrypt and decrypt using the ARN of the provided key.
    strict_encrypt_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**encrypt_kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, encrypted_message_header = client.encrypt(
        source=source_plaintext, key_provider=strict_encrypt_key_provider
    )

    # For each original master key, create a strict key provider that only lists that key and decrypt the encrypted
    # message using that provider. Note: in order for decrypt to succeed, the key_ids value must be the key ARN of the
    # CMK.
    for key_arn in key_arns:
        decrypt_kwargs = dict(key_ids=[key_arn])
        if botocore_session is not None:
            encrypt_kwargs["botocore_session"] = botocore_session

        strict_decrypt_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**decrypt_kwargs)
        plaintext, decrypted_message_header = client.decrypt(
            source=ciphertext, key_provider=strict_decrypt_key_provider
        )

        # Verify that the original message and the decrypted message are the same
        assert source_plaintext == plaintext

        # Verify that the encryption context of the encrypted message and decrypted message match
        assert all(
            pair in encrypted_message_header.encryption_context.items()
            for pair in decrypted_message_header.encryption_context.items()
        )
