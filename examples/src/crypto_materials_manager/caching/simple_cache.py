# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
The default cryptographic materials manager (CMM)
creates new encryption and decryption materials
on every call.
This means every encrypted message is protected by a unique data key,
but it also means that you need to interact with your key management system
in order to process any message.
If this causes performance, operations, or cost issues for you,
you might benefit from data key caching.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html

This examples shows how to configure the caching CMM
to reuse data keys across multiple encrypted messages.

In this example, we use an AWS KMS customer master key (CMK),
but you can use other key management options with the AWS Encryption SDK.
For examples that demonstrate how to use other key management configurations,
see the ``keyring`` and ``master_key_provider`` directories.

In this example, we use the one-step encrypt and decrypt APIs.
"""
import aws_encryption_sdk
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a KMS keyring with a single CMK.

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

    # Create the keyring that determines how your data keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk)

    # Create the caching cryptographic materials manager using your keyring.
    cmm = CachingCryptoMaterialsManager(
        keyring=keyring,
        # The cache is where the caching CMM stores the materials.
        #
        # LocalCryptoMaterialsCache gives you a local, in-memory, cache.
        cache=LocalCryptoMaterialsCache(capacity=100),
        # max_age determines how long the caching CMM will reuse materials.
        #
        # This example uses two minutes.
        # In production, always choose as small a value as possible
        # that works for your requirements.
        max_age=120.0,
        # max_messages_encrypted determines how many messages
        # the caching CMM will protect with the same materials.
        #
        # In production, always choose as small a value as possible
        # that works for your requirements.
        max_messages_encrypted=10,
    )

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, materials_manager=cmm
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same cryptographic materials manager you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, materials_manager=cmm)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
