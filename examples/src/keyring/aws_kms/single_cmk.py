# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to configure and use a KMS keyring with a single KMS CMK.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring

For an example of how to use the KMS keyring with CMKs in multiple regions,
see the ``keyring/aws_kms/multiple_regions`` example.

For examples of how to use the KMS keyring with custom client configurations,
see the ``keyring/aws_kms/custom_client_supplier``
and ``keyring/aws_kms/custom_kms_client_config`` examples.

For examples of how to use the KMS keyring in discovery mode on decrypt,
see the ``keyring/aws_kms/discovery_decrypt``
and ``keyring/aws_kms/discovery_decrypt_with_preferred_region`` examples.
"""
import aws_encryption_sdk


def run(aws_kms_cmk, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under one KMS customer master key (CMK).

    :param str aws_kms_cmk: Amazon Resource Name (ARN) of the KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    kwargs = dict(key_ids=[aws_kms_cmk])

    if botocore_session is not None:
        kwargs["botocore_session"] = botocore_session

    # Create master key provider using the ARN of the key and the session (botocore_session)
    kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, encrypted_message_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, key_provider=kms_key_provider
    )

    # Decrypt the encrypted message using the AWS Encryption SDK. It returns the decrypted message and the header
    plaintext, decrypted_message_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=kms_key_provider)

    # Check if the original message and the decrypted message are the same
    assert source_plaintext == plaintext

    # Check if the headers of the encrypted message and decrypted message match
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header.encryption_context.items()
    )
