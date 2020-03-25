# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
One use-case that we have seen customers need is
the ability to enjoy the benefits of AWS KMS during normal operation
but retain the ability to decrypt encrypted messages without access to AWS KMS.
This example shows how you can use the multi-keyring to achieve this
by combining a KMS keyring with a raw RSA keyring.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-multi-keyring

For more examples of how to use the KMS keyring, see the ``keyring/aws_kms`` examples.

For more examples of how to use the raw RSA keyring, see the ``keyring/raw_rsa`` examples.

In this example we generate a RSA keypair
but in practice you would want to keep your private key in an HSM
or other key management system.

In this example, we use the one-step encrypt and decrypt APIs.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring
from aws_encryption_sdk.keyrings.multi import MultiKeyring
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate configuring a keyring to use an AWS KMS CMK and a RSA wrapping key.

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

    # Generate an RSA private key to use with your keyring.
    # In practice, you should get this key from a secure key management system such as an HSM.
    #
    # The National Institute of Standards and Technology (NIST) recommends a minimum of 2048-bit keys for RSA.
    # https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths
    #
    # Why did we use this public exponent?
    # https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    # Collect the public key from the private key.
    public_key = private_key.public_key()

    # Create the encrypt keyring that only has access to the public key.
    escrow_encrypt_keyring = RawRSAKeyring(
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
    escrow_decrypt_keyring = RawRSAKeyring(
        # The key namespace and key name MUST match the encrypt keyring.
        key_namespace="some managed raw keys",
        key_name=b"my RSA wrapping key",
        private_wrapping_key=private_key,
        # The wrapping algorithm MUST match the encrypt keyring.
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    )

    # Create the KMS keyring that you will use for decryption during normal operations.
    kms_keyring = KmsKeyring(generator_key_id=aws_kms_cmk)

    # Combine the KMS keyring and the escrow encrypt keyring using the multi-keyring.
    encrypt_keyring = MultiKeyring(generator=kms_keyring, children=[escrow_encrypt_keyring])

    # Encrypt your plaintext data using the multi-keyring.
    ciphertext, encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=encrypt_keyring
    )

    # Verify that the header contains the expected number of encrypted data keys (EDKs).
    # It should contain one EDK for KMS and one for the escrow key.
    assert len(encrypt_header.encrypted_data_keys) == 2

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data separately using the KMS keyring and the escrow decrypt keyring.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted_kms, decrypt_header_kms = aws_encryption_sdk.decrypt(source=ciphertext, keyring=kms_keyring)
    decrypted_escrow, decrypt_header_escrow = aws_encryption_sdk.decrypt(
        source=ciphertext, keyring=escrow_decrypt_keyring
    )

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted_kms == source_plaintext
    assert decrypted_escrow == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header_kms.encryption_context.items())
    assert set(encryption_context.items()) <= set(decrypt_header_escrow.encryption_context.items())
