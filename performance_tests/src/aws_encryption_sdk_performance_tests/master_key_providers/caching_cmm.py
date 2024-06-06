# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the Caching Cryptographic Materials Manager (CMM) with KMS Master Key Provider."""

import aws_encryption_sdk


def create_cmm(
    kms_key_id: str,
    max_age_in_cache: float,
    cache_capacity: int
):
    """Demonstrate how to create a Caching CMM.

    Usage: create_cmm(kms_key_id, max_age_in_cache, cache_capacity)
    :param kms_key_id: Amazon Resource Name (ARN) of the KMS customer master key
    :type kms_key_id: str
    :param max_age_in_cache: Maximum time in seconds that a cached entry can be used
    :type max_age_in_cache: float
    :param cache_capacity: Maximum number of entries to retain in cache at once
    :type cache_capacity: int
    """
    # Security thresholds
    #   Max messages (or max bytes per) data key are optional
    max_messages_encrypted = 100

    # Create a master key provider for the KMS customer master key (CMK)
    key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[kms_key_id])

    # Create a local cache
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(cache_capacity)

    # Create a caching CMM
    caching_cmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=key_provider,
        cache=cache,
        max_age=max_age_in_cache,
        max_messages_encrypted=max_messages_encrypted,
    )

    return caching_cmm


def encrypt_using_cmm(
    plaintext_data: bytes,
    caching_cmm: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
):
    """Demonstrate how to encrypt plaintext data using a Caching CMM.

    Usage: encrypt_using_cmm(plaintext_data, caching_cmm)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param caching_cmm: Crypto Materials Manager to use for encryption.
    :type caching_cmm: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    ciphertext_data, _ = client.encrypt(
        source=plaintext_data,
        materials_manager=caching_cmm
    )

    return ciphertext_data


def decrypt_using_cmm(
    ciphertext_data: bytes,
    caching_cmm: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
):
    """Demonstrate how to decrypt ciphertext data using a Caching CMM.

    Usage: decrypt_using_cmm(ciphertext_data, caching_cmm)
    :param ciphertext_data: ciphertext data you want to decrypt
    :type: bytes
    :param caching_cmm: Crypto Materials Manager to use for encryption.
    :type caching_cmm: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    decrypted_plaintext_data, _ = client.decrypt(
        source=ciphertext_data,
        materials_manager=caching_cmm
    )

    return decrypted_plaintext_data
