# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to configure and use an AWS KMS keyring with with CMKs in multiple regions.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring

For an example of how to use the AWS KMS keyring with a single CMK,
see the ``keyring/aws_kms/single_cmk`` example.

For examples of how to use the AWS KMS keyring with custom client configurations,
see the ``keyring/aws_kms/custom_client_supplier``
and ``keyring/aws_kms/custom_kms_client_config`` examples.

For examples of how to use the AWS KMS keyring in discovery mode on decrypt,
see the ``keyring/aws_kms/discovery_decrypt``,
``keyring/aws_kms/discovery_decrypt_in_region_only``,
and ``keyring/aws_kms/discovery_decrypt_with_preferred_region`` examples.
"""
import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Sequence  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def run(aws_kms_generator_cmk, aws_kms_additional_cmks, source_plaintext):
    # type: (str, Sequence[str], bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS keyring with CMKs in multiple regions.

    :param str aws_kms_generator_cmk: The ARN of the primary AWS KMS CMK
    :param List[str] aws_kms_additional_cmks: Additional ARNs of secondary AWS KMS CMKs
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

    # Create the keyring that will encrypt your data keys under all requested CMKs.
    many_cmks_keyring = AwsKmsKeyring(generator_key_id=aws_kms_generator_cmk, key_ids=aws_kms_additional_cmks)

    # Create keyrings that each only use one of the CMKs.
    # We will use these later to demonstrate that any of the CMKs can be used to decrypt the message.
    #
    # We provide these in "key_ids" rather than "generator_key_id"
    # so that these keyrings cannot be used to generate a new data key.
    # We will only be using them on decrypt.
    single_cmk_keyring_that_generated = AwsKmsKeyring(key_ids=[aws_kms_generator_cmk])
    single_cmk_keyring_that_encrypted = AwsKmsKeyring(key_ids=[aws_kms_additional_cmks[0]])

    # Encrypt your plaintext data using the keyring that uses all requests CMKs.
    ciphertext, encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=many_cmks_keyring
    )

    # Verify that the header contains the expected number of encrypted data keys (EDKs).
    # It should contain one EDK for each CMK.
    assert len(encrypt_header.encrypted_data_keys) == len(aws_kms_additional_cmks) + 1

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data separately using the single-CMK keyrings.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted_1, decrypt_header_1 = aws_encryption_sdk.decrypt(
        source=ciphertext, keyring=single_cmk_keyring_that_generated
    )
    decrypted_2, decrypt_header_2 = aws_encryption_sdk.decrypt(
        source=ciphertext, keyring=single_cmk_keyring_that_encrypted
    )

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted_1 == source_plaintext
    assert decrypted_2 == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header_1.encryption_context.items())
    assert set(encryption_context.items()) <= set(decrypt_header_2.encryption_context.items())
