# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This is a migration example for moving to the AWS KMS Keyring from AWS KMS master key provider (MKP)

The AWS KMS keyring uses symmetric encryption KMS keys to generate, encrypt and
decrypt data keys. This example creates a KMS Keyring and KMS MKP and
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

For more information on how to use KMS keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html
"""
import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk

EXAMPLE_DATA: bytes = b"Hello World"

DEFAULT_ENCRYPTION_CONTEXT : Dict[str, str] = {
    "encryption": "context",
    "is not": "secret",
    "but adds": "useful metadata",
    "that can help you": "be confident that",
    "the data you are handling": "is what you think it is",
}


def create_kms_client(aws_region="us-west-2"):
    """Create an AWS KMS client.

    Usage: create_kms_client(aws_region)
    :param aws_region: AWS region to use for KMS client.
    :type aws_region: string
    """
    # Create a boto3 client for KMS.
    kms_client = boto3.client('kms', region_name=aws_region)

    return kms_client


def create_keyring(
    kms_key_id: str
):
    """Demonstrate how to create an AWS KMS keyring.

    Usage: create_keyring(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use.
    :type kms_key_id: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    # Create a boto3 client for KMS.
    kms_client = create_kms_client()

    # Create a KMS keyring
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=kms_key_id,
        kms_client=kms_client
    )

    keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=keyring_input
    )

    return keyring


def encrypt_using_keyring(
    plaintext_data: bytes,
    keyring: IKeyring,
    client: aws_encryption_sdk.EncryptionSDKClient
):
    """Demonstrate how to encrypt plaintext data using an AWS KMS keyring.

    Usage: encrypt_using_keyring(plaintext_data, keyring)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param keyring: Keyring to use for encryption.
    :type keyring: IKeyring
    :param client: AWS Encryption SDK client.
    :type client: aws_encryption_sdk.EncryptionSDKClient
    """
    ciphertext_data, _ = client.encrypt(
        source=plaintext_data,
        keyring=keyring,
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT
    )

    return ciphertext_data


def decrypt_using_keyring(
    ciphertext_data: bytes,
    keyring: IKeyring,
    client: aws_encryption_sdk.EncryptionSDKClient
):
    """Demonstrate how to decrypt ciphertext data using an AWS KMS keyring.

    Usage: decrypt_using_keyring(ciphertext_data, keyring)
    :param ciphertext_data: ciphertext data you want to decrypt
    :type: bytes
    :param keyring: Keyring to use for decryption.
    :type keyring: IKeyring
    :param client: AWS Encryption SDK client.
    :type client: aws_encryption_sdk.EncryptionSDKClient
    """
    decrypted_plaintext_data, _ = client.decrypt(
        source=ciphertext_data,
        keyring=keyring
    )

    return decrypted_plaintext_data


def create_key_provider(
    kms_key_id: str
):
    """Demonstrate how to create an AWS KMS master key provider.

    Usage: create_key_provider(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use.
    :type kms_key_id: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    # Create a KMS master key provider.
    key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        kms_key_id,
    ])

    return key_provider


def encrypt_using_key_provider(
    plaintext_data: bytes,
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider,
    client: aws_encryption_sdk.EncryptionSDKClient
):
    """Demonstrate how to encrypt plaintext data using an AWS KMS master key provider.

    Usage: encrypt_using_key_provider(plaintext_data, key_provider)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param key_provider: Master key provider to use for encryption.
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param client: AWS Encryption SDK client.
    :type client: aws_encryption_sdk.EncryptionSDKClient
    """
    ciphertext_data, _ = client.encrypt(
        source=plaintext_data,
        key_provider=key_provider,
        encryption_context=DEFAULT_ENCRYPTION_CONTEXT
    )

    return ciphertext_data


def decrypt_using_key_provider(
    ciphertext_data: bytes,
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider,
    client: aws_encryption_sdk.EncryptionSDKClient
):
    """Demonstrate how to decrypt ciphertext data using an AWS KMS master key provider.

    Usage: decrypt_using_key_provider(ciphertext_data, key_provider)
    :param ciphertext_data: ciphertext data you want to decrypt
    :type: bytes
    :param key_provider: Master key provider to use for decryption.
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param client: AWS Encryption SDK client.
    :type client: aws_encryption_sdk.EncryptionSDKClient
    """
    decrypted_plaintext_data, _ = client.decrypt(
        source=ciphertext_data,
        key_provider=key_provider
    )

    return decrypted_plaintext_data


def migration_aws_kms_key(
    kms_key_id: str
):
    """Demonstrate a migration example for moving to an AWS KMS keyring from AWS KMS MKP.

    Usage: migration_aws_kms_key(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use for encryption and
    decryption of your data keys.
    :type kms_key_id: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    # 1a. Create a AWS KMS Keyring
    aws_kms_keyring = create_keyring(kms_key_id=kms_key_id)

    # 1b. Create a AWS KMS Master Key Provider
    aws_kms_master_key_provider = create_key_provider(kms_key_id=kms_key_id)

    # 2a. Encrypt EXAMPLE_DATA using AWS KMS Keyring
    ciphertext_keyring = encrypt_using_keyring(
        plaintext_data=EXAMPLE_DATA,
        keyring=aws_kms_keyring,
        client=client
    )

    # 2b. Encrypt EXAMPLE_DATA using AWS KMS Master Key Provider
    ciphertext_mkp = encrypt_using_key_provider(
        plaintext_data=EXAMPLE_DATA,
        key_provider=aws_kms_master_key_provider,
        client=client
    )

    # Note: The ciphertexts obtained by encrypting EXAMPLE_DATA using keyring and MKP
    # (that is ciphertext_keyring and ciphertext_mkp) are not the same because the ESDK
    # generates different data keys each time for encryption of the data. But both
    # ciphertexts when decrypted using keyring and MKP should give the same plaintext result.

    # 3. Decrypt the ciphertext_keyring using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_keyring_using_keyring = decrypt_using_keyring(
        ciphertext_data=ciphertext_keyring,
        keyring=aws_kms_keyring,
        client=client
    )

    decrypted_ciphertext_keyring_using_mkp = decrypt_using_key_provider(
        ciphertext_data=ciphertext_keyring,
        key_provider=aws_kms_master_key_provider,
        client=client
    )

    assert decrypted_ciphertext_keyring_using_keyring == decrypted_ciphertext_keyring_using_mkp \
        and decrypted_ciphertext_keyring_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"

    # 4. Decrypt the ciphertext_mkp using both the keyring and MKP and ensure the
    # resulting plaintext is the same and also equal to EXAMPLE_DATA
    decrypted_ciphertext_mkp_using_keyring = decrypt_using_keyring(
        ciphertext_data=ciphertext_mkp,
        keyring=aws_kms_keyring,
        client=client
    )

    decrypted_ciphertext_mkp_using_mkp = decrypt_using_key_provider(
        ciphertext_data=ciphertext_mkp,
        key_provider=aws_kms_master_key_provider,
        client=client
    )

    assert decrypted_ciphertext_mkp_using_keyring == decrypted_ciphertext_mkp_using_mkp \
        and decrypted_ciphertext_mkp_using_keyring == EXAMPLE_DATA, \
        "Decrypted outputs using keyring and master key provider are not the same"
