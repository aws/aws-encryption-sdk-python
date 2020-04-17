# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Before there were keyrings, there were master key providers.
Master key providers were the original configuration structure
that we provided for defining how you want to protect your data keys.

The AWS KMS master key provider was the tool that we provided for interacting with AWS KMS.
Like the AWS KMS keyring,
the AWS KMS master key provider encrypts with all CMKs that you identify,
but unlike the AWS KMS keyring,
the AWS KMS master key provider always attempts to decrypt
*any* data keys that were encrypted under an AWS KMS CMK.
We have found that separating these two behaviors
makes it more clear what behavior to expect,
so that is what we did with the AWS KMS keyring and the AWS KMS discovery keyring.
However, as you migrate away from master key providers to keyrings,
you might need to replicate the behavior of the AWS KMS master key provider.

This example shows how to configure a keyring that behaves like an AWS KMS master key provider.

For more examples of how to use the AWS KMS keyring,
see the ``keyring/aws_kms`` directory.
"""
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
from aws_encryption_sdk.keyrings.multi import MultiKeyring


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate how to create a keyring that behaves like an AWS KMS master key provider.

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

    # This is the master key provider whose behavior we want to replicate.
    #
    # On encrypt, this master key provider only uses the single target AWS KMS CMK.
    # However, on decrypt, this master key provider attempts to decrypt
    # any data keys that were encrypted under an AWS KMS CMK.
    _master_key_provider_to_replicate = KMSMasterKeyProvider(key_ids=[aws_kms_cmk])

    # Create a keyring that encrypts and decrypts using a single AWS KMS CMK.
    single_cmk_keyring = AwsKmsKeyring(generator_key_id=aws_kms_cmk)

    # Create an AWS KMS discovery keyring that will attempt to decrypt
    # any data keys that were encrypted under an AWS KMS CMK.
    discovery_keyring = AwsKmsKeyring(is_discovery=True)

    # Combine the single-CMK and discovery keyrings
    # to create a keyring that behaves like an AWS KMS master key provider.
    keyring = MultiKeyring(generator=single_cmk_keyring, children=[discovery_keyring])

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same keyring you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
