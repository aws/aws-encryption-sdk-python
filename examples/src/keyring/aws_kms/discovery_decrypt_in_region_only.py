# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
When you give the KMS keyring specific key IDs it will use those CMKs and nothing else.
This is true both on encrypt and on decrypt.
However, sometimes you need more flexibility on decrypt,
especially if you don't know which CMK was used to encrypt a message.
To address this need, you can use a KMS discovery keyring.
The KMS discovery keyring does nothing on encrypt
but attempts to decrypt *any* data keys that were encrypted under a KMS CMK.

However, sometimes you need to be a *bit* more restrictive than that.
To address this need, you can use a client supplier that restricts the regions a KMS keyring can talk to.

This example shows how to configure and use a KMS regional discovery keyring that is restricted to one region.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring

For an example of how to use the KMS keyring with CMKs in multiple regions,
see the ``keyring/aws_kms/multiple_regions`` example.

For examples of how to use the KMS keyring with custom client configurations,
see the ``keyring/aws_kms/custom_client_supplier``
and ``keyring/aws_kms/custom_kms_client_config`` examples.

For examples of how to use the KMS discovery keyring on decrypt,
see the ``keyring/aws_kms/discovery_decrypt``
and ``keyring/aws_kms/discovery_decrypt_with_preferred_region`` examples.
"""
import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import AllowRegionsClientSupplier


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate configuring a KMS keyring to only work within a single region.

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
    encrypt_keyring = KmsKeyring(generator_key_id=aws_kms_cmk)

    # Extract the region from the CMK ARN.
    decrypt_region = aws_kms_cmk.split(":", 4)[3]

    # Create the KMS discovery keyring that we will use on decrypt.
    #
    # Because we do not specify any key IDs, this keyring is created in discovery mode.
    #
    # The client supplier that we specify here will only supply clients for the specified region.
    # The keyring only attempts to decrypt data keys if it can get a client for that region,
    # so this keyring will now ignore any data keys that were encrypted under a CMK in another region.
    decrypt_keyring = KmsKeyring(client_supplier=AllowRegionsClientSupplier(allowed_regions=[decrypt_region]))

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=encrypt_keyring
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the KMS discovery keyring.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=decrypt_keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
