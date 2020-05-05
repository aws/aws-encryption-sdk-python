# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example is intended to serve as reference material for users migrating away from master key providers.
We recommend using keyrings rather than master key providers.
For examples using keyrings, see the ``examples/src/keyrings`` directory.

This example shows how to configure and use a raw RSA master key using a PEM-encoded RSA private key.

The most commonly used encodings for RSA keys tend to be PEM and DER.
The raw RSA master key supports loading both public and private keys from PEM encoding.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider

In this example, we use the one-step encrypt and decrypt APIs.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.key_providers.raw import RawMasterKey, WrappingKey


def run(source_plaintext):
    # type: (bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a raw RSA master key loaded from a PEM-encoded key.

    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    # Remember that your encryption context is NOT SECRET.
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Generate an RSA private key to use with your master key.
    # In practice, you should get this key from a secure key management system such as an HSM.
    #
    # The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
    # https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
    #
    # Why did we use this public exponent?
    # https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    # Serialize the RSA private key to PEM encoding.
    # This or DER encoding is likely to be what you get from your key management system in practice.
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Create the master key that determines how your data keys are protected.
    #
    # WrappingKey can only load PEM-encoded keys.
    master_key = RawMasterKey(
        # The provider ID and key ID are defined by you
        # and are used by the raw RSA master key
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        provider_id="some managed raw keys",  # provider ID corresponds to key namespace for keyrings
        key_id=b"my RSA wrapping key",  # key ID corresponds to key name for keyrings
        wrapping_key=WrappingKey(
            wrapping_key=private_key_pem,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
            # The wrapping algorithm tells the raw RSA master key
            # how to use your wrapping key to encrypt data keys.
            #
            # We recommend using RSA_OAEP_SHA256_MGF1.
            # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        ),
    )

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, key_provider=master_key
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same master key you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=master_key)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
