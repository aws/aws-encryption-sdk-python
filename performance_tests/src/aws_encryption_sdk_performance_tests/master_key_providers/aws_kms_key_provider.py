# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the AWS KMS master key provider."""

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy


def create_key_provider(
    kms_key_id: str
):
    """Demonstrate how to create an AWS KMS master key-provider.

    Usage: create_key_provider(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use.
    :type kms_key_id: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    # Create a KMS master key-provider.
    key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        kms_key_id,
    ])

    return key_provider


def encrypt_using_key_provider(
    plaintext_data: bytes,
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
):
    """Demonstrate how to encrypt plaintext data using an AWS KMS master key-provider.

    Usage: encrypt_using_key_provider(plaintext_data, key_provider)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param key_provider: Master key provider to use for encryption.
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    _, _ = client.encrypt(
        source=plaintext_data,
        key_provider=key_provider
    )


def decrypt_using_key_provider(
    ciphertext_data: bytes,
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
):
    """Demonstrate how to decrypt ciphertext data using an AWS KMS master key-provider.

    Usage: decrypt_using_key_provider(ciphertext_data, key_provider)
    :param ciphertext_data: ciphertext data you want to decrypt
    :type: bytes
    :param key_provider: Master key provider to use for decryption.
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    _, _ = client.decrypt(
        source=ciphertext_data,
        key_provider=key_provider
    )
