# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the Raw RSA Keyring

The Raw RSA keyring performs asymmetric encryption and decryption of data keys in local memory
with RSA public and private keys that you provide. In this example, we define the RSA keys to
encrypt and decrypt the data keys.

You need to generate, store, and protect the private key, preferably in a
hardware security module (HSM) or key management system.
The encryption function encrypts the data key under the RSA public key. The decryption function
decrypts the data key using the private key.

This example creates a Raw RSA Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
4. The original ciphertext is not decryptable using a keyring with a different RSA key pair
These sanity checks are for demonstration in the example only. You do not need these in your code.

A Raw RSA keyring that encrypts and decrypts must include an asymmetric public key and private
key pair. However, you can encrypt data with a Raw RSA keyring that has only a public key,
and you can decrypt data with a Raw RSA keyring that has only a private key. This example requires
the user to either provide both private and public keys, or not provide any keys and the example
generates both to test encryption and decryption. If you configure a Raw RSA keyring with a
public and private key, be sure that they are part of the same key pair. Some language
implementations of the AWS Encryption SDK will not construct a Raw RSA keyring with keys
from different pairs. Others rely on you to verify that your keys are from the same key pair.
You can include any Raw RSA keyring in a multi-keyring.

For more information on how to use Raw RSA keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-rsa-keyring.html
"""
import sys

from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateRawRsaKeyringInput, PaddingScheme
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError


EXAMPLE_DATA: bytes = b"Hello World"


def should_generate_new_rsa_key_pair(public_key_file_name, private_key_file_name):
    """Returns True if user doesn't provide keys, and we need to generate them;
    Returns False if the user has already provided both public and private keys
    Raises a ValueError if the user only provides one of private_key and public_key

    Usage: should_generate_new_rsa_key_pair(public_key_file_name, private_key_file_name)
    """
    # If only one of public_key and private_key files is provided, raise a ValueError
    if (public_key_file_name and not private_key_file_name)\
            or (not public_key_file_name and private_key_file_name):
        raise ValueError("Either both public and private keys should be provided! Or no keys \
                             should be provided and the example can create the keys for you!")

    # If no keys are provided, we should generate a new rsa key pair, so return True
    if not public_key_file_name and not private_key_file_name:
        return True

    # If both keys are already provided, return False
    return False


def generate_rsa_keys():
    """Generates a 4096-bit RSA public and private key pair

    Usage: generate_rsa_keys()
    """
    ssh_rsa_exponent = 65537
    bit_strength = 4096
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=ssh_rsa_exponent,
        key_size=bit_strength
    )

    # This example choses a particular type of encoding, format and encryption_algorithm
    # Users can choose the PublicFormat, PrivateFormat and encryption_algorithm that align most
    # with their use-cases
    public_key = key.public_key().public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key = key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=crypto_serialization.NoEncryption()
    )

    return public_key, private_key


def create_rsa_keyring(public_key, private_key):
    """Create a Raw RSA keyring using the key pair

    Usage: create_rsa_keyring(public_key, private_key)
    """
    # 1. The key namespace and key name are defined by you.
    # and are used by the Raw RSA keyring
    # For more information, see
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-rsa-keyring.html
    key_name_space = "Some managed raw keys"
    key_name = "My 4096-bit RSA wrapping key"

    # 2. Create a Raw RSA keyring
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateRawRsaKeyringInput = CreateRawRsaKeyringInput(
        key_namespace=key_name_space,
        key_name=key_name,
        padding_scheme=PaddingScheme.OAEP_SHA256_MGF1,
        public_key=public_key,
        private_key=private_key
    )

    raw_rsa_keyring: IKeyring = mat_prov.create_raw_rsa_keyring(
        input=keyring_input
    )

    return raw_rsa_keyring


def encrypt_and_decrypt_with_keyring(public_key_file_name=None, private_key_file_name=None):
    """Demonstrate an encrypt/decrypt cycle using a Raw RSA keyring
    with user defined keys. If no keys are present, generate new RSA
    public and private keys and use them to create a Raw RSA keyring

    Usage: encrypt_and_decrypt_with_keyring(public_key_file_name, private_key_file_name)
    """
    # 1. Instantiate the encryption SDK client.
    # This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
    # which enforces that this client only encrypts using committing algorithm suites and enforces
    # that this client will only decrypt encrypted messages that were created with a committing
    # algorithm suite.
    # This is the default commitment policy if you were to build the client as
    # `client = aws_encryption_sdk.EncryptionSDKClient()`.
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    # 2. Create encryption context.
    # Remember that your encryption context is NOT SECRET.
    # For more information, see
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context: Dict[str, str] = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # 3. Create a Raw RSA keyring.
    #   If you have provided keys in a PEM file, they will be loaded into the keyring.
    #   Otherwise, a key pair will be randomly generated for you.

    # Check if we need to generate an RSA key pair
    should_generate_new_rsa_key_pair_bool = \
        should_generate_new_rsa_key_pair(public_key_file_name=public_key_file_name,
                                         private_key_file_name=private_key_file_name)

    # If user doesn't provide the keys, that is, if should_generate_new_rsa_key_pair_bool is True
    # generate a new RSA public and private key pair
    if should_generate_new_rsa_key_pair_bool:
        public_key, private_key = generate_rsa_keys()
    else:
        # If user provides the keys, read the keys from the files
        with open(public_key_file_name, "r", encoding='utf-8') as f:
            public_key = f.read()

        # Convert the public key from a string to bytes
        public_key = bytes(public_key, 'utf-8')

        with open(private_key_file_name, "r", encoding='utf-8') as f:
            private_key = f.read()

        # Convert the private key from a string to bytes
        private_key = bytes(private_key, 'utf-8')

    # Create the keyring
    raw_rsa_keyring = create_rsa_keyring(public_key=public_key, private_key=private_key)

    # 4. Encrypt the data with the encryptionContext
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=raw_rsa_keyring,
        encryption_context=encryption_context
    )

    # 5. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 6. Decrypt your encrypted data using the same keyring you used on encrypt.
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=raw_rsa_keyring
    )

    # 7. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 8. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # The next part of the example creates a new RSA keyring (for Bob) to demonstrate that
    # decryption of the original ciphertext is not possible with a different keyring (Bob's).
    # (This is an example for demonstration; you do not need to do this in your own code.)

    # 9. Create a new Raw RSA keyring for Bob
    # Generate new keys
    public_key_bob, private_key_bob = generate_rsa_keys()

    # Create the keyring
    raw_rsa_keyring_bob = create_rsa_keyring(public_key=public_key_bob, private_key=private_key_bob)

    # 10. Test decrypt for the original ciphertext using raw_rsa_keyring_bob
    try:
        plaintext_bytes_bob, _ = client.decrypt(  # pylint: disable=unused-variable
            source=ciphertext,
            keyring=raw_rsa_keyring_bob
        )

        raise AssertionError("client.decrypt should throw an error of type AWSEncryptionSDKClientError!")
    except AWSEncryptionSDKClientError:
        pass
