# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This is a migration example for moving to the Raw AES Keyring from Raw AES master key provider (MKP)

The Raw AES keyring lets you use an AES symmetric key that you provide as a wrapping key that
protects your data key. You need to generate, store, and protect the key material,
preferably in a hardware security module (HSM) or key management system. Use a Raw AES keyring
when you need to provide the wrapping key and encrypt the data keys locally or offline.

This example defines classes for Raw AES Keyring and Raw AES MKP and
then encrypts a custom input EXAMPLE_DATA with an encryption context using both
the keyring and MKP. The example then decrypts the ciphertext using both keyring and MKPs.
This example also includes some sanity checks for demonstration:
1. Decryption of these ciphertexts encrypted using keyring and MKP
   is possible using both KMS keyring and KMS MKP
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

DEFAULT_KEY_NAME_SPACE = "Some managed raw keys"

DEFAULT_KEY_NAME = "My 256-bit AES wrapping key"


class RawAesKeyring():
    """Class for creating a Raw AES Keyring and using it for encryption and decryption"""

    @staticmethod
    def create_keyring():
        """Demonstrate how to create a Raw AES keyring.

        Usage: create_keyring()
        """
        # We fix the static key in order to make the test deterministic
        static_key = DEFAULT_AES_256_STATIC_KEY

        mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
            config=MaterialProvidersConfig()
        )

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

    @staticmethod
    def encrypt_using_keyring(
        plaintext_data: bytes,
        keyring: IKeyring
    ):
        """Demonstrate how to encrypt plaintext data using a Raw AES keyring.

        Usage: encrypt_using_keyring(plaintext_data, keyring)
        :param plaintext_data: plaintext data you want to encrypt
        :type: bytes
        :param keyring: Keyring to use for encryption.
        :type keyring: IKeyring
        """
        client = aws_encryption_sdk.EncryptionSDKClient()

        ciphertext_data, _ = client.encrypt(
            source=plaintext_data,
            keyring=keyring,
            encryption_context=DEFAULT_ENCRYPTION_CONTEXT
        )

        return ciphertext_data

    @staticmethod
    def decrypt_using_keyring(
        ciphertext_data: bytes,
        keyring: IKeyring
    ):
        """Demonstrate how to decrypt ciphertext data using a Raw AES keyring.

        Usage: decrypt_using_keyring(ciphertext_data, keyring)
        :param ciphertext_data: ciphertext data you want to decrypt
        :type: bytes
        :param keyring: Keyring to use for decryption.
        :type keyring: IKeyring
        """
        client = aws_encryption_sdk.EncryptionSDKClient()

        decrypted_plaintext_data, _ = client.decrypt(
            source=ciphertext_data,
            keyring=keyring
        )

        return decrypted_plaintext_data


# This is a helper class necessary for the Raw AES master key provider
class StaticRandomMasterKeyProvider(RawMasterKeyProvider):
    """Generates 256-bit keys for each unique key ID."""

    # The Provider ID (or Provider) field in the JceMasterKey and RawMasterKey is
    # equivalent to key namespace in the Raw keyrings
    provider_id = DEFAULT_KEY_NAME_SPACE

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Initialize empty map of keys."""
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        """Returns a static, randomly-generated symmetric key for the specified key ID.

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


class RawAesMasterKeyProvider():
    """Class for creating a Raw AES MKP and using it for encryption and decryption"""

    @staticmethod
    def create_key_provider():
        """Demonstrate how to create a Raw AES master key provider.

        Usage: create_key_provider()
        """
        # Create a Raw AES master key provider.

        # The Key ID field in the JceMasterKey and RawMasterKey is equivalent to key name in the Raw keyrings
        key_id = DEFAULT_KEY_NAME
        key_provider = StaticRandomMasterKeyProvider()
        key_provider.add_master_key(key_id)

        return key_provider

    @staticmethod
    def encrypt_using_key_provider(
        plaintext_data: bytes,
        key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    ):
        """Demonstrate how to encrypt plaintext data using a Raw AES master key provider.

        Usage: encrypt_using_key_provider(plaintext_data, key_provider)
        :param plaintext_data: plaintext data you want to encrypt
        :type: bytes
        :param key_provider: Master key provider to use for encryption.
        :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
        """
        client = aws_encryption_sdk.EncryptionSDKClient()

        ciphertext_data, _ = client.encrypt(
            source=plaintext_data,
            key_provider=key_provider,
            encryption_context=DEFAULT_ENCRYPTION_CONTEXT
        )

        return ciphertext_data

    @staticmethod
    def decrypt_using_key_provider(
        ciphertext_data: bytes,
        key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    ):
        """Demonstrate how to decrypt ciphertext data using a Raw AES master key provider.

        Usage: decrypt_using_key_provider(ciphertext_data, key_provider)
        :param ciphertext_data: ciphertext data you want to decrypt
        :type: bytes
        :param key_provider: Master key provider to use for decryption.
        :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
        """
        client = aws_encryption_sdk.EncryptionSDKClient()

        decrypted_plaintext_data, _ = client.decrypt(
            source=ciphertext_data,
            key_provider=key_provider
        )

        return decrypted_plaintext_data


def migration_to_raw_aes_keyring_from_raw_aes_master_key_provider():
    """Demonstrate a migration example for moving from a Raw AES keyring to Raw AES MKP.

    Usage: migration_to_raw_aes_keyring_from_raw_aes_master_key_provider()
    """

    # 1a. Create a Raw AES Keyring
    raw_aes_keyring = RawAesKeyring.create_keyring()

    # 1b. Create a Raw AES Master Key Provider
    raw_aes_master_key_provider = RawAesMasterKeyProvider.create_key_provider()

    # 2a. Encrypt EXAMPLE_DATA using Raw AES Keyring
    ciphertext_keyring = RawAesKeyring.encrypt_using_keyring(
        plaintext_data=EXAMPLE_DATA,
        keyring=raw_aes_keyring
    )

    # 2b. Encrypt EXAMPLE_DATA using Raw AES Master Key Provider
    ciphertext_mkp = RawAesMasterKeyProvider.encrypt_using_key_provider(
        plaintext_data=EXAMPLE_DATA,
        key_provider=raw_aes_master_key_provider
    )

    # Note: The ciphertexts obtained by encrypting EXAMPLE_DATA using keyring and MKP
    # (that is ciphertext_keyring and ciphertext_mkp) are not the same because the ESDK
    # generates different data keys each time for encryption of the data. But both
    # ciphertexts when decrypted using keyring and MKP should give the same plaintext result.

    # 3. Decrypt the ciphertext_keyring using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_keyring_using_keyring = RawAesKeyring.decrypt_using_keyring(
        ciphertext_data=ciphertext_keyring,
        keyring=raw_aes_keyring
    )

    decrypted_ciphertext_keyring_using_mkp = RawAesMasterKeyProvider.decrypt_using_key_provider(
        ciphertext_data=ciphertext_keyring,
        key_provider=raw_aes_master_key_provider
    )

    assert decrypted_ciphertext_keyring_using_keyring == decrypted_ciphertext_keyring_using_mkp \
        and decrypted_ciphertext_keyring_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"

    # 4. Decrypt the ciphertext_mkp using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_mkp_using_keyring = RawAesKeyring.decrypt_using_keyring(
        ciphertext_data=ciphertext_mkp,
        keyring=raw_aes_keyring
    )

    decrypted_ciphertext_mkp_using_mkp = RawAesMasterKeyProvider.decrypt_using_key_provider(
        ciphertext_data=ciphertext_mkp,
        key_provider=raw_aes_master_key_provider
    )

    assert decrypted_ciphertext_mkp_using_keyring == decrypted_ciphertext_mkp_using_mkp \
        and decrypted_ciphertext_mkp_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"
