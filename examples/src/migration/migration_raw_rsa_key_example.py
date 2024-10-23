# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This is a migration example for moving to the Raw RSA Keyring from Raw RSA master key provider (MKP)

The Raw RSA keyring performs asymmetric encryption and decryption of data keys in local memory
with RSA public and private keys that you provide. In this example, we define the RSA keys to
encrypt and decrypt the data keys.

You need to generate, store, and protect the private key, preferably in a
hardware security module (HSM) or key management system.
The encryption function encrypts the data key under the RSA public key. The decryption function
decrypts the data key using the private key.

This example creates a Raw RSA Keyring and Raw RSA MKP and
then encrypts a custom input EXAMPLE_DATA with the same encryption context using both
the keyring and MKP. The example then decrypts the ciphertexts using both keyring and MKPs.
This example also includes some sanity checks for demonstration:
1. Decryption of these ciphertexts encrypted using keyring and MKP
   is possible using both Raw RSA keyring and Raw RSA MKP
2. Both decrypted plaintexts are same and match EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

Note: The ciphertexts obtained by encrypting EXAMPLE_DATA using keyring and MKP are not
the same because the ESDK generates different data keys each time for encryption of the data.
But both ciphertexts when decrypted using keyring and MKP will give the same plaintext result.

For more information on how to use Raw RSA keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-rsa-keyring.html
"""
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateRawRsaKeyringInput, PaddingScheme
from aws_cryptographic_material_providers.mpl.references import IKeyring
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

EXAMPLE_DATA: bytes = b"Hello World"

DEFAULT_ENCRYPTION_CONTEXT : Dict[str, str] = {
    "encryption": "context",
    "is not": "secret",
    "but adds": "useful metadata",
    "that can help you": "be confident that",
    "the data you are handling": "is what you think it is",
}

# The key namespace in the Raw keyrings is equivalent to Provider ID (or Provider) field
# in the Raw Master Key Providers
DEFAULT_KEY_NAME_SPACE = "Some managed raw keys"

# The key name in the Raw keyrings is equivalent to the Key ID field
# in the Raw Master Key Providers
DEFAULT_KEY_NAME = "My 4096-bit RSA wrapping key"


def generate_rsa_keys_helper():
    """Generates a 4096-bit RSA public and private key pair

    Usage: generate_rsa_keys_helper()
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


DEFAULT_RSA_PUBLIC_KEY, DEFAULT_RSA_PRIVATE_KEY = generate_rsa_keys_helper()


def create_keyring(public_key, private_key):
    """Demonstrate how to create a Raw RSA keyring using the key pair.

    Usage: create_keyring(public_key, private_key)
    """
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # The key namespace in the Raw keyrings is equivalent to Provider ID (or Provider) field
    # in the Raw Master Key Providers
    # The key name in the Raw keyrings is equivalent to the Key ID field
    # in the Raw Master Key Providers
    keyring_input: CreateRawRsaKeyringInput = CreateRawRsaKeyringInput(
        key_namespace=DEFAULT_KEY_NAME_SPACE,
        key_name=DEFAULT_KEY_NAME,
        padding_scheme=PaddingScheme.OAEP_SHA256_MGF1,
        public_key=public_key,
        private_key=private_key
    )

    keyring: IKeyring = mat_prov.create_raw_rsa_keyring(
        input=keyring_input
    )

    return keyring


# This is a helper class necessary for the Raw RSA master key provider.
# In the StaticMasterKeyProvider, we fix the static key to
# DEFAULT_RSA_PRIVATE_KEY in order to make the test deterministic.
# Thus, both the Raw RSA keyring and Raw RSA MKP have the same private_key
# and we are able to encrypt data using keyrings and decrypt using MKP and vice versa
# In practice, users should generate a new random key pair for each key id.
class StaticMasterKeyProvider(RawMasterKeyProvider):
    """Provides 4096-bit RSA keys consistently per unique key id."""

    # The key namespace in the Raw keyrings is equivalent to Provider ID (or Provider) field
    # in the Raw Master Key Providers
    provider_id = DEFAULT_KEY_NAME_SPACE

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Initialize empty map of keys."""
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        """Retrieves a static, RSA key for the specified key id.

        :param str key_id: User-defined ID for the static key
        :returns: Wrapping key that contains the specified static key
        :rtype: :class:`aws_encryption_sdk.internal.crypto.WrappingKey`
        """
        try:
            static_key = self._static_keys[key_id]
        except KeyError:
            # We fix the static key in order to make the test deterministic
            # In practice, you should get this key from a secure key management system such as an HSM.
            # Also, in practice, users should generate a new key pair for each key id in
            # the StaticMasterKeyProvider.
            static_key = DEFAULT_RSA_PRIVATE_KEY
            self._static_keys[key_id] = static_key
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=static_key,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
        )


def create_key_provider():
    """Demonstrate how to create a Raw RSA master key provider.

    Usage: create_key_provider()
    """
    # Create a Raw RSA master key provider.

    # The key name in the Raw keyrings is equivalent to the Key ID field
    # in the Raw Master Key Providers
    key_id = DEFAULT_KEY_NAME

    # In this example, we fix the static key to DEFAULT_RSA_PRIVATE_KEY in both the keyring
    # and MKP (for MKP, we fix the static key in StaticMasterKeyProvider) in order to make
    # the test deterministic. Thus, both the Raw RSA keyring and Raw RSA MKP have the same
    # private_key and we are able to encrypt data using keyrings and decrypt using MKP
    # and vice versa. In practice, users should generate a new key pair for each key id in
    # the StaticMasterKeyProvider.
    key_provider = StaticMasterKeyProvider()
    key_provider.add_master_key(key_id)

    return key_provider


def migration_raw_rsa_key(
    public_key=DEFAULT_RSA_PUBLIC_KEY,
    private_key=DEFAULT_RSA_PRIVATE_KEY
):
    """Demonstrate a migration example for moving to a Raw RSA keyring from Raw RSA MKP.

    Usage: migration_raw_rsa_key(public_key, private_key)
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    # 1a. Create a Raw RSA Keyring
    raw_rsa_keyring = create_keyring(public_key=public_key, private_key=private_key)

    # 1b. Create a Raw RSA Master Key Provider

    # In this example, we fix the static key to DEFAULT_RSA_PRIVATE_KEY in both the keyring
    # and MKP (for MKP, we fix the static key in StaticMasterKeyProvider) in order to make
    # the test deterministic. Thus, both the Raw RSA keyring and Raw RSA MKP have the same
    # private_key and we are able to encrypt data using keyrings and decrypt using MKP
    # and vice versa. In practice, users should generate a new key pair for each key id in
    # the StaticMasterKeyProvider.
    raw_rsa_master_key_provider = create_key_provider()

    # 2a. Encrypt EXAMPLE_DATA using Raw RSA Keyring
    ciphertext_keyring, encrypted_header_keyring = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=raw_rsa_keyring,
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT
    )

    # 2b. Encrypt EXAMPLE_DATA using Raw RSA Master Key Provider
    ciphertext_mkp, encrypted_header_mkp = client.encrypt(
        source=EXAMPLE_DATA,
        key_provider=raw_rsa_master_key_provider,
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT
    )

    # Note: The ciphertexts obtained by encrypting EXAMPLE_DATA using keyring and MKP
    # (that is ciphertext_keyring and ciphertext_mkp) are not the same because the ESDK
    # generates different data keys each time for encryption of the data. But both
    # ciphertexts when decrypted using keyring and MKP will give the same plaintext result.

    # 3. Decrypt the ciphertext_keyring using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_keyring_using_keyring, _ = client.decrypt(
        source=ciphertext_keyring,
        keyring=raw_rsa_keyring,
        # Provide the encryption context that was supplied to the encrypt method
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT,
    )

    decrypted_ciphertext_keyring_using_mkp, decrypted_header_keyring_using_mkp = client.decrypt(
        source=ciphertext_keyring,
        key_provider=raw_rsa_master_key_provider
    )

    # Legacy MasterKeyProviders do not support providing encryption context on decrypt.
    # If decrypting with a legacy MasterKeyProvider, you should manually verify
    # that the encryption context used in the decrypt operation
    # includes all key pairs from the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    assert all(
        pair in decrypted_header_keyring_using_mkp.encryption_context.items()
        for pair in encrypted_header_keyring.encryption_context.items()
    )

    assert decrypted_ciphertext_keyring_using_keyring == decrypted_ciphertext_keyring_using_mkp \
        and decrypted_ciphertext_keyring_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"

    # 4. Decrypt the ciphertext_mkp using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_mkp_using_keyring, _ = client.decrypt(
        source=ciphertext_mkp,
        keyring=raw_rsa_keyring,
        # Provide the encryption context that was supplied to the encrypt method
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT,
    )

    decrypted_ciphertext_mkp_using_mkp, decrypted_header_mkp_using_mkp = client.decrypt(
        source=ciphertext_mkp,
        key_provider=raw_rsa_master_key_provider
    )

    # Legacy MasterKeyProviders do not support providing encryption context on decrypt.
    # If decrypting with a legacy MasterKeyProvider, you should manually verify
    # that the encryption context used in the decrypt operation
    # includes all key pairs from the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    assert all(
        pair in decrypted_header_mkp_using_mkp.encryption_context.items()
        for pair in encrypted_header_mkp.encryption_context.items()
    )

    assert decrypted_ciphertext_mkp_using_keyring == decrypted_ciphertext_mkp_using_mkp \
        and decrypted_ciphertext_mkp_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"
