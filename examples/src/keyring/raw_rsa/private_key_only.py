# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This examples shows how to configure and use a raw RSA keyring using a pre-loaded RSA private key.

If your RSA key is in PEM or DER format,
see the ``keyring/raw_rsa/private_key_only_from_pem`` example.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring

In this example, we use the one-step encrypt and decrypt APIs.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring


def run(source_plaintext):
    # type: (bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a raw RSA keyring.

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
    # In practice, you should get this key from a secure key management system such as an HSM.
    #
    # The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
    # https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
    #
    # Why did we use this public exponent?
    # https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    # Create the keyring that determines how your data keys are protected.
    keyring = RawRSAKeyring(
        # The key namespace and key name are defined by you
        # and are used by the raw RSA keyring
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        #
        # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
        key_namespace="some managed raw keys",
        key_name=b"my RSA wrapping key",
        private_wrapping_key=private_key,
        # The wrapping algorithm tells the raw RSA keyring
        # how to use your wrapping key to encrypt data keys.
        #
        # We recommend using RSA_OAEP_SHA256_MGF1.
        # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    )

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
