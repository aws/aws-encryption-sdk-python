# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example showing encryption of a value already in memory using one KMS CMK, then decryption of the ciphertext using
a DiscoveryAwsKmsMasterKeyProvider.
"""
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.key_providers.kms import DiscoveryFilter


def encrypt_decrypt(key_arn, source_plaintext, botocore_session=None):
    """Encrypts a string under one KMS customer master key (CMK), then decrypts it using discovery mode.

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    encrypt_kwargs = dict(key_ids=[key_arn])

    if botocore_session is not None:
        encrypt_kwargs["botocore_session"] = botocore_session

    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Create strict master key provider that is only allowed to encrypt and decrypt using the ARN of the provided key.
    strict_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**encrypt_kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, encrypted_message_header = client.encrypt(source=source_plaintext, key_provider=strict_key_provider)

    # Create a second master key provider in discovery mode that does not explicitly list the key used to encrypt.
    # Note: The discovery_filter argument is optional; if you omit this, the AWS Encryption SDK attempts to
    # decrypt any ciphertext it receives.
    arn = arn_from_str(key_arn)
    decrypt_kwargs = dict(discovery_filter=DiscoveryFilter(account_ids=[arn.account_id], partition=arn.partition))
    if botocore_session is not None:
        encrypt_kwargs["botocore_session"] = botocore_session
    discovery_key_provider = aws_encryption_sdk.DiscoveryAwsKmsMasterKeyProvider(**decrypt_kwargs)

    # Decrypt the encrypted message using the AWS Encryption SDK. It returns the decrypted message and the header.
    plaintext, decrypted_message_header = client.decrypt(source=ciphertext, key_provider=discovery_key_provider)

    # Verify that the original message and the decrypted message are the same
    assert source_plaintext == plaintext

    # Verify that the encryption context of the encrypted message and decrypted message match
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header.encryption_context.items()
    )
