# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example is provided as a reference for users migrating away from master key providers.
We recommend that all new use should use keyrings.
For examples using keyrings, see the ``examples/src/keyrings`` directory.

The KMS master key provider uses any key IDs that you specify on encrypt,
but attempts to decrypt *any* data keys that were encrypted under a KMS CMK.
This means that you do not need to know which CMKs were used to encrypt a message.

This example shows how to configure and use a KMS master key provider to decrypt without provider key IDs.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider

For an example of how to use the KMS master key with a single CMK,
see the ``master_key_provider/aws_kms/single_cmk`` example.

For an example of how to use the KMS master key provider with CMKs in multiple regions,
see the ``master_key_provider/aws_kms/multiple_regions`` example.
"""
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyProvider


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate configuring a KMS master key provider for decryption.

    :param str aws_kms_cmk: The ARN of an AWS KMS CMK that protects data keys
    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the master key that determines how your data keys are protected.
    encrypt_master_key = KMSMasterKey(key_id=aws_kms_cmk)

    # Create a KMS master key provider to use on decrypt.
    decrypt_master_key_provider = KMSMasterKeyProvider()

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, key_provider=encrypt_master_key
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the KMS master key provider.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=decrypt_master_key_provider)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
