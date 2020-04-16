# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example is intended to serve as reference material for users migrating away from master key providers.
We recommend using keyrings rather than master key providers.
For examples using keyrings, see the ``examples/src/keyrings`` directory.

One use-case that we have seen customers need is
the ability to enjoy the benefits of AWS KMS during normal operation
but retain the ability to decrypt encrypted messages without access to AWS KMS.
This example shows how you can achieve this
by combining an AWS KMS master key with a raw RSA master key.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#master-key-provider

For more examples of how to use the AWS KMS master key provider, see the ``master_key_provider/aws_kms`` examples.

For more examples of how to use the raw RSA master key, see the ``master_key_provider/raw_rsa`` examples.

In this example we generate an RSA keypair
but in practice you would want to keep your private key in an HSM
or other key management system.

In this example, we use the one-step encrypt and decrypt APIs.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from aws_encryption_sdk.key_providers.raw import RawMasterKey, WrappingKey


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate configuring a master key provider to use an AWS KMS CMK and an RSA wrapping key.

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

    # Collect the public key from the private key.
    public_key = private_key.public_key()

    # Serialize the RSA public key to PEM encoding.
    # This or DER encoding is likely to be what you get from your key management system in practice.
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create the encrypt master key that only has access to the public key.
    escrow_encrypt_master_key = RawMasterKey(
        # The provider ID and key ID are defined by you
        # and are used by the raw RSA master key
        # to determine whether it should attempt to decrypt
        # an encrypted data key.
        provider_id="some managed raw keys",  # provider ID corresponds to key namespace for keyrings
        key_id=b"my RSA wrapping key",  # key ID corresponds to key name for keyrings
        wrapping_key=WrappingKey(
            wrapping_key=public_key_pem,
            wrapping_key_type=EncryptionKeyType.PUBLIC,
            # The wrapping algorithm tells the raw RSA master key
            # how to use your wrapping key to encrypt data keys.
            #
            # We recommend using RSA_OAEP_SHA256_MGF1.
            # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        ),
    )

    # Create the decrypt master key that has access to the private key.
    escrow_decrypt_master_key = RawMasterKey(
        # The key namespace and key name MUST match the encrypt master key.
        provider_id="some managed raw keys",  # provider ID corresponds to key namespace for keyrings
        key_id=b"my RSA wrapping key",  # key ID corresponds to key name for keyrings
        wrapping_key=WrappingKey(
            wrapping_key=private_key_pem,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
            # The wrapping algorithm MUST match the encrypt master key.
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        ),
    )

    # Create the AWS KMS master key that you will use for decryption during normal operations.
    kms_master_key = KMSMasterKeyProvider(key_ids=[aws_kms_cmk])

    # Add the escrow encrypt master key to the AWS KMS master key.
    kms_master_key.add_master_key_provider(escrow_encrypt_master_key)

    # Encrypt your plaintext data using the combined master keys.
    ciphertext, encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, key_provider=kms_master_key
    )

    # Verify that the header contains the expected number of encrypted data keys (EDKs).
    # It should contain one EDK for AWS KMS and one for the escrow key.
    assert len(encrypt_header.encrypted_data_keys) == 2

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data separately using the AWS KMS master key and the escrow decrypt master key.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted_kms, decrypt_header_kms = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=kms_master_key)
    decrypted_escrow, decrypt_header_escrow = aws_encryption_sdk.decrypt(
        source=ciphertext, key_provider=escrow_decrypt_master_key
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
