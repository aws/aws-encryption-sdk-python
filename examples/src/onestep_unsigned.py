# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example shows how to specify an algorithm suite
when using the one-step encrypt and decrypt APIs.

In this example, we use an AWS KMS customer master key (CMK),
but you can use other key management options with the AWS Encryption SDK.
For examples that demonstrate how to use other key management configurations,
see the ``keyring`` and ``master_key_provider`` directories.

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


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate requesting a specific algorithm suite through the one-step encrypt/decrypt APIs.

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

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext,
        encryption_context=encryption_context,
        keyring=keyring,
        # Here we can specify the algorithm suite that we want to use.
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same keyring you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    #
    # You do not need to specify the algorithm suite on decrypt
    # because the header message includes the algorithm suite identifier.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
