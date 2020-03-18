# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
One of the benefits of asymmetric encryption
is that you can encrypt with just the public key.
This means that you give someone the ability to encrypt
without giving them the ability to decrypt.

The raw RSA keyring supports encrypt-only operations
when it only has access to a public key.

This example shows how to construct and use the raw RSA keyring
to encrypt with only the public key and decrypt with the private key.

If your RSA key is in PEM or DER format,
see the ``keyring/raw_rsa/private_key_only_from_pem`` example.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring

In this example, we use the one-step encrypt and decrypt APIs.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring


def run(source_plaintext):
    # type: (bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using separate public and private raw RSA keyrings.

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
    # Why did we use this public exponent?
    # https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    # Collect the public key from the private key.
    public_key = private_key.public_key()

    # The keyring determines how your data keys are protected.
    #
    # Create the encrypt keyring that only has access to the public key.
    public_key_keyring = RawRSAKeyring(
        # The key namespace and key name are defined by you
        # and are used by the raw RSA keyring
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        #
        # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-raw-rsa-keyring
        key_namespace="some managed raw keys",
        key_name=b"my RSA wrapping key",
        public_wrapping_key=public_key,
        # The wrapping algorithm tells the raw RSA keyring
        # how to use your wrapping key to encrypt data keys.
        #
        # We recommend using RSA_OAEP_SHA256_MGF1.
        # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    )

    # Create the decrypt keyring that has access to the private key.
    private_key_keyring = RawRSAKeyring(
        # The key namespace and key name MUST match the encrypt keyring.
        key_namespace="some managed raw keys",
        key_name=b"my RSA wrapping key",
        private_wrapping_key=private_key,
        # The wrapping algorithm MUST match the encrypt keyring.
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    )

    # Encrypt your plaintext data using the encrypt keyring.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=public_key_keyring
    )

    # Verify that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the decrypt keyring.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=private_key_keyring)

    # Try to decrypt your encrypted data using the *encrypt* keyring.
    # This demonstrates that you cannot decrypt using the public key.
    try:
        aws_encryption_sdk.decrypt(source=ciphertext, keyring=public_key_keyring)
    except AWSEncryptionSDKClientError:
        # The public key cannot decrypt.
        # Reaching this point means everything is working as expected.
        pass
    else:
        # Show that the public keyring could not decrypt.
        raise AssertionError("This will never happen!")

    # Verify that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
