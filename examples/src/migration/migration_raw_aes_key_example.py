# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This is a migration example for moving to the Raw AES Keyring from Raw AES master key provider (MKP)

The Raw AES keyring lets you use an AES symmetric key that you provide as a wrapping key that
protects your data key. You need to generate, store, and protect the key material,
preferably in a hardware security module (HSM) or key management system. Use a Raw AES keyring
when you need to provide the wrapping key and encrypt the data keys locally or offline.

This example creates a Raw AES Keyring and Raw AES MKP and
then encrypts a custom input EXAMPLE_DATA with the same encryption context using both
the keyring and MKP. The example then decrypts the ciphertexts using both keyring and MKPs.
This example also includes some sanity checks for demonstration:
1. Decryption of these ciphertexts encrypted using keyring and MKP
   is possible using both Raw AES keyring and Raw AES MKP
2. Both decrypted plaintexts are same and match EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

Note: The ciphertexts obtained by encrypting EXAMPLE_DATA using keyring and MKP are not
the same because the ESDK generates different data keys each time for encryption of the data.
But both ciphertexts when decrypted using keyring and MKP should give the same plaintext result.

For more information on how to use Raw AES keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-aes-keyring.html
"""
import secrets

from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import AesWrappingAlg, CreateRawAesKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
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

DEFAULT_AES_256_STATIC_KEY = secrets.token_bytes(32)

# The key namespace in the Raw keyrings is equivalent to Provider ID (or Provider) field
# in the Raw Master Key Providers
DEFAULT_KEY_NAME_SPACE = "Some managed raw keys"

# The key name in the Raw keyrings is equivalent to the Key ID field
# in the Raw Master Key Providers
DEFAULT_KEY_NAME = "My 256-bit AES wrapping key"


def create_keyring():
    """Demonstrate how to create a Raw AES keyring.

    Usage: create_keyring()
    """
    # We fix the static key in order to make the test deterministic
    static_key = DEFAULT_AES_256_STATIC_KEY

    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # The key namespace in the Raw keyrings is equivalent to Provider ID (or Provider) field
    # in the Raw Master Key Providers
    # The key name in the Raw keyrings is equivalent to the Key ID field
    # in the Raw Master Key Providers
    keyring_input: CreateRawAesKeyringInput = CreateRawAesKeyringInput(
        key_namespace=DEFAULT_KEY_NAME_SPACE,
        key_name=DEFAULT_KEY_NAME,
        wrapping_key=static_key,
        wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
    )

    keyring: IKeyring = mat_prov.create_raw_aes_keyring(
        input=keyring_input
    )

    return keyring


# This is a helper class necessary for the Raw AES master key provider
# In the StaticMasterKeyProvider, we fix the static key to
# DEFAULT_AES_256_STATIC_KEY in order to make the test deterministic.
# Thus, both the Raw AES keyring and Raw AES MKP have the same key
# and we are able to encrypt data using keyrings and decrypt using MKP and vice versa
# In practice, users should generate a new random key for each key id.
class StaticMasterKeyProvider(RawMasterKeyProvider):
    """Generates 256-bit keys for each unique key ID."""

    # The key namespace in the Raw keyrings is equivalent to Provider ID (or Provider) field
    # in the Raw Master Key Providers
    provider_id = DEFAULT_KEY_NAME_SPACE

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Initialize empty map of keys."""
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        """Returns a static, symmetric key for the specified key ID.

        :param str key_id: Key ID
        :returns: Wrapping key that contains the specified static key
        :rtype: :class:`aws_encryption_sdk.internal.crypto.WrappingKey`
        """
        try:
            static_key = self._static_keys[key_id]
        except KeyError:
            # We fix the static key in order to make the test deterministic
            # In practice, you should get this key from a secure key management system such as an HSM.
            static_key = DEFAULT_AES_256_STATIC_KEY
            self._static_keys[key_id] = static_key
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def create_key_provider():
    """Demonstrate how to create a Raw AES master key provider.

    Usage: create_key_provider()
    """
    # Create a Raw AES master key provider.

    # The key name in the Raw keyrings is equivalent to the Key ID field
    # in the Raw Master Key Providers
    key_id = DEFAULT_KEY_NAME
    key_provider = StaticMasterKeyProvider()
    key_provider.add_master_key(key_id)

    return key_provider


def migration_raw_aes_key():
    """Demonstrate a migration example for moving to a Raw AES keyring from Raw AES MKP.

    Usage: migration_raw_aes_key()
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    # 1a. Create a Raw AES Keyring
    raw_aes_keyring = create_keyring()

    # 1b. Create a Raw AES Master Key Provider
    raw_aes_master_key_provider = create_key_provider()

    # 2a. Encrypt EXAMPLE_DATA using Raw AES Keyring
    ciphertext_keyring, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=raw_aes_keyring,
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT
    )

    # 2b. Encrypt EXAMPLE_DATA using Raw AES Master Key Provider
    ciphertext_mkp, _ = client.encrypt(
        source=EXAMPLE_DATA,
        key_provider=raw_aes_master_key_provider,
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT
    )

    # Note: The ciphertexts obtained by encrypting EXAMPLE_DATA using keyring and MKP
    # (that is ciphertext_keyring and ciphertext_mkp) are not the same because the ESDK
    # generates different data keys each time for encryption of the data. But both
    # ciphertexts when decrypted using keyring and MKP should give the same plaintext result.

    # 3. Decrypt the ciphertext_keyring using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_keyring_using_keyring, _ = client.decrypt(
        source=ciphertext_keyring,
        keyring=raw_aes_keyring
    )

    decrypted_ciphertext_keyring_using_mkp, _ = client.decrypt(
        source=ciphertext_keyring,
        key_provider=raw_aes_master_key_provider
    )

    assert decrypted_ciphertext_keyring_using_keyring == decrypted_ciphertext_keyring_using_mkp \
        and decrypted_ciphertext_keyring_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"

    # 4. Decrypt the ciphertext_mkp using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_mkp_using_keyring, _ = client.decrypt(
        source=ciphertext_mkp,
        keyring=raw_aes_keyring
    )

    decrypted_ciphertext_mkp_using_mkp, _ = client.decrypt(
        source=ciphertext_mkp,
        key_provider=raw_aes_master_key_provider
    )

    assert decrypted_ciphertext_mkp_using_keyring == decrypted_ciphertext_mkp_using_mkp \
        and decrypted_ciphertext_mkp_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"
