# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
When you store RSA keys, you have to serialize them somehow.

This examples shows how to configure and use a raw RSA keyring using a PEM-encoded RSA private key.

The most commonly used encodings for RSA keys tend to be PEM and DER.
The raw RSA keyring supports loading both public and private keys from these encodings.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring

In this example, we use the one-step encrypt and decrypt APIs.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring


def run(source_plaintext):
    # type: (bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a raw RSA keyring loaded from a PEM-encoded key.

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

    # Generate an RSA private key to use with your keyring.
    # In practice, you should get this key from a secure key management system.
    #
    # Why did we use this public exponent?
    # https://latacora.singles/2018/04/03/cryptographic-right-answers.html
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    # Serialize the RSA private key to PEM encoding.
    # This or DER encoding likely to be what you get from your key management system in practice.
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Create the keyring that determines how your data keys are protected.
    #
    # If your key is encoded using DER, you can use RawRSAKeyring.from_der_encoding
    keyring = RawRSAKeyring.from_pem_encoding(
        # The key namespace and key name are defined by you
        # and are used by the raw RSA keyring
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        #
        # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
        key_namespace="some managed raw keys",
        key_name=b"my RSA wrapping key",
        private_encoded_key=private_key_pem,
        # The wrapping algorithm tells the raw RSA keyring
        # how to use your wrapping key to encrypt data keys.
        #
        # Why did we use this wrapping algorithm?
        # https://latacora.singles/2018/04/03/cryptographic-right-answers.html
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    )

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    )

    # Verify that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same keyring you used on encrypt.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Verify that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
