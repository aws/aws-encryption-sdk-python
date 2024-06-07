# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the Raw AES master key provider."""

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

from ..utils.util import PerfTestUtils


class StaticRandomMasterKeyProvider(RawMasterKeyProvider):
    """Generates 256-bit keys for each unique key ID."""

    # The Provider ID (or Provider) field in the JceMasterKey and RawMasterKey is
    # equivalent to key namespace in the Raw keyrings
    provider_id = "Some managed raw keys"

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Initialize empty map of keys."""
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        """Returns a static, randomly-generated symmetric key for the specified key ID.

        :param str key_id: Key ID
        :returns: Wrapping key that contains the specified static key
        :rtype: :class:`aws_encryption_sdk.internal.crypto.WrappingKey`
        """
        try:
            static_key = self._static_keys[key_id]
        except KeyError:
            # We fix the static key in order to make the test deterministic
            # In practice, you should get this key from a secure key management system such as an HSM.
            static_key = PerfTestUtils.DEFAULT_AES_256_STATIC_KEY
            self._static_keys[key_id] = static_key
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def create_key_provider():
    """Demonstrate how to create a Raw AES master key provider.

    Usage: create_key_provider()
    """
    # Create a Raw AES master key provider.

    # The Key ID field in the JceMasterKey and RawMasterKey is equivalent to key name in the Raw keyrings
    key_id = "My 256-bit AES wrapping key"
    key_provider = StaticRandomMasterKeyProvider()
    key_provider.add_master_key(key_id)

    return key_provider


def encrypt_using_key_provider(
    plaintext_data: bytes,
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
):
    """Demonstrate how to encrypt plaintext data using a Raw AES master key provider.

    Usage: encrypt_using_key_provider(plaintext_data, key_provider)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param key_provider: Master key provider to use for encryption.
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    ciphertext_data, _ = client.encrypt(
        source=plaintext_data,
        key_provider=key_provider
    )

    return ciphertext_data


def decrypt_using_key_provider(
    ciphertext_data: bytes,
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
):
    """Demonstrate how to decrypt ciphertext data using a Raw AES master key provider.

    Usage: decrypt_using_key_provider(ciphertext_data, key_provider)
    :param ciphertext_data: ciphertext data you want to decrypt
    :type: bytes
    :param key_provider: Master key provider to use for decryption.
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    decrypted_plaintext_data, _ = client.decrypt(
        source=ciphertext_data,
        key_provider=key_provider
    )

    return decrypted_plaintext_data
