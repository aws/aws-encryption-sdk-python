# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example is intended to serve as reference material for users migrating away from master key providers.
We recommend using keyrings rather than master key providers.
For examples using keyrings, see the ``examples/src/keyrings`` directory.

This example shows how to configure and use a KMS master key provider with with CMKs in multiple regions.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider

For an example of how to use the KMS master key with a single CMK,
see the ``master_key_provider/aws_kms/single_cmk`` example.

For an example of how to use the KMS master key provider in discovery mode on decrypt,
see the ``master_key_provider/aws_kms/discovery_decrypt`` example.
"""
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyProvider

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Sequence  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def run(aws_kms_generator_cmk, aws_kms_additional_cmks, source_plaintext):
    # type: (str, Sequence[str], bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a KMS master key provider with CMKs in multiple regions.

    :param str aws_kms_generator_cmk: The ARN of the primary AWS KMS CMK
    :param List[str] aws_kms_additional_cmks: Additional ARNs of secondary KMS CMKs
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

    # Create the master key provider that will encrypt your data keys under all requested CMKs.
    #
    # The KMS master key provider generates the data key using the first key ID in the list.
    key_ids = [aws_kms_generator_cmk]
    key_ids.extend(aws_kms_additional_cmks)
    master_key_provider = KMSMasterKeyProvider(key_ids=key_ids)

    # Create master keys that each only use one of the CMKs.
    # We will use these later to demonstrate that any of the CMKs can be used to decrypt the message.
    single_cmk_master_key_that_generated = KMSMasterKey(key_id=aws_kms_generator_cmk)
    single_cmk_master_key_that_encrypted = KMSMasterKey(key_id=aws_kms_additional_cmks[0])

    # Encrypt your plaintext data using the master key provider that uses all requests CMKs.
    ciphertext, encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, key_provider=master_key_provider
    )

    # Verify that the header contains the expected number of encrypted data keys (EDKs).
    # It should contain one EDK for each CMK.
    assert len(encrypt_header.encrypted_data_keys) == len(aws_kms_additional_cmks) + 1

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data separately using the single-CMK master keys.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted_1, decrypt_header_1 = aws_encryption_sdk.decrypt(
        source=ciphertext, key_provider=single_cmk_master_key_that_generated
    )
    decrypted_2, decrypt_header_2 = aws_encryption_sdk.decrypt(
        source=ciphertext, key_provider=single_cmk_master_key_that_encrypted
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
