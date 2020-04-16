# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example of encryption with data key caching."""
import aws_encryption_sdk


def run(aws_kms_cmk, max_age_in_cache=10.0, cache_capacity=10):
    """Encrypts a string using an AWS KMS customer master key (CMK) and data key caching.

    :param str aws_kms_cmk: Amazon Resource Name (ARN) of the AWS KMS customer master key
    :param float max_age_in_cache: Maximum time in seconds that a cached entry can be used
    :param int cache_capacity: Maximum number of entries to retain in cache at once
    """
    # Data to be encrypted
    my_data = "My plaintext data"

    # Security thresholds
    #   Max messages (or max bytes per) data key are optional
    MAX_ENTRY_MESSAGES = 100

    # Create an encryption context
    encryption_context = {"purpose": "test"}

    # Create a master key provider for the AWS KMS customer master key (CMK)
    key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[aws_kms_cmk])

    # Create a local cache
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(cache_capacity)

    # Create a caching CMM
    caching_cmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=key_provider,
        cache=cache,
        max_age=max_age_in_cache,
        max_messages_encrypted=MAX_ENTRY_MESSAGES,
    )

    # When the call to encrypt data specifies a caching CMM,
    # the encryption operation uses the data key cache specified
    # in the caching CMM
    encrypted_message, _header = aws_encryption_sdk.encrypt(
        source=my_data, materials_manager=caching_cmm, encryption_context=encryption_context
    )

    return encrypted_message
