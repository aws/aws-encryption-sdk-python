# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
When you give the KMS keyring specific key IDs it will use those CMKs and nothing else.
This is true both on encrypt and on decrypt.
However, sometimes you need more flexibility on decrypt,
especially when you don't know which CMKs were used to encrypt a message.
To address this need, you can use a KMS discovery keyring.
The KMS discovery keyring does nothing on encrypt,
but attempts to decrypt *any* data keys that were encrypted under a KMS CMK.

However, sometimes you need to be a *bit* more restrictive than that.
To address this need, you can use a client supplier to restrict what regions a KMS keyring can talk to.

A more complex but more common use-case is that you would *prefer* to stay within a region,
but you would rather make calls to other regions than fail to decrypt the message.
In this case, you want a keyring that will try to decrypt data keys in this region first,
then try other regions.

This example shows how to configure and use a multi-keyring with the KMS keyring
to prefer the current AWS region while also failing over to other AWS regions.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring

For an example of how to use the KMS keyring with CMKs in multiple regions,
see the ``keyring/aws_kms/multiple_regions`` example.

For examples of how to use the KMS keyring with custom client configurations,
see the ``keyring/aws_kms/custom_client_supplier``
and ``keyring/aws_kms/custom_kms_client_config`` examples.

For examples of how to use the KMS discovery keyring on decrypt,
see the ``keyring/aws_kms/discovery_decrypt``
and ``keyring/aws_kms/discovery_decrypt_in_region_only`` examples.
"""
from boto3.session import Session

import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import AllowRegionsClientSupplier, DenyRegionsClientSupplier
from aws_encryption_sdk.keyrings.multi import MultiKeyring


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate configuring a KMS discovery-like keyring a particular AWS region and failover to others.

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
    encrypt_keyring = AwsKmsKeyring(generator_key_id=aws_kms_cmk)

    # To create our decrypt keyring, we need to know our current default AWS region.
    #
    # Create a throw-away boto3 session to discover the default region.
    local_region = Session().region_name

    # Now, use that region name to create two KMS discovery keyrings:
    #
    # One that only works in the local region
    local_region_decrypt_keyring = AwsKmsKeyring(
        is_discovery=True, client_supplier=AllowRegionsClientSupplier(allowed_regions=[local_region])
    )
    # and one that will work in any other region but NOT the local region.
    other_regions_decrypt_keyring = AwsKmsKeyring(
        is_discovery=True, client_supplier=DenyRegionsClientSupplier(denied_regions=[local_region])
    )

    # Finally, combine those two keyrings into a multi-keyring.
    #
    # The multi-keyring steps through its member keyrings in the order that you provide them,
    # attempting to decrypt every encrypted data key with each keyring before moving on to the next keyring.
    # Because of this, other_regions_decrypt_keyring will not be called
    # unless local_region_decrypt_keyring fails to decrypt every encrypted data key.
    decrypt_keyring = MultiKeyring(children=[local_region_decrypt_keyring, other_regions_decrypt_keyring])

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=encrypt_keyring
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the multi-keyring.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=decrypt_keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
