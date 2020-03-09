# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to specify an algorithm suite
when using the one-shot encrypt and decrypt APIs.

For the purposes of this example, we demonstrate using AWS KMS,
but you can use other key management options with the AWS Encryption SDK.
Look in the ``keyring`` and ``master_key_provider`` directories
for examples that demonstrate how to use other key management configurations.

The default algorithm suite includes a message-level signature
that protects you from an attacker who has *decrypt* but not *encrypt* capability
for a wrapping key that you used when encrypting a message
under multiple wrapping keys.

However, if all of your readers and writers have the same permissions,
then this additional protection does not always add value.
This example shows you how to select another algorithm suite
that has all of the other properties of the default suite
but does not include a message-level signature.
"""
import aws_encryption_sdk
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring


def run(aws_kms_cmk_arn, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate requesting a specific algorithm suite through the one-shot encrypt/decrypt APIs.

    :param str aws_kms_cmk_arn: AWS KMS CMK ARN to use to protect data keys
    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the keyring that determines how your keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk_arn)

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext,
        encryption_context=encryption_context,
        keyring=keyring,
        # Here we can specify the algorithm suite that we want to use.
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
    )

    # Verify that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    #
    # We do not need to specify the algorithm suite on decrypt
    # because the header message includes the algorithm suite identifier.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Verify that the "cycled" (encrypted then decrypted) plaintext
    # is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation matches what you expect.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
