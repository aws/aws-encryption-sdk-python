# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the AWS KMS keyring."""

import aws_encryption_sdk
import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring


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


def create_kms_client(aws_region="us-west-2"):
    """Create an AWS KMS client.

    Usage: create_kms_client(aws_region)
    :param aws_region: AWS region to use for KMS client.
    :type aws_region: string
    """
    # Create a boto3 client for KMS.
    kms_client = boto3.client('kms', region_name=aws_region)

    return kms_client


def create_keyring_given_kms_client(
    kms_key_id: str,
    kms_client: boto3.client,
):
    """Demonstrate how to create an AWS KMS keyring with given KMS client.

    Usage: create_keyring(kms_key_id, kms_client)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use.
    :type kms_key_id: string
    :param kms_client: boto3 client for KMS.
    :type kms_client: boto3.client

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
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
    keyring: IKeyring
):
    """Demonstrate how to encrypt plaintext data using an AWS KMS keyring.

    Usage: encrypt_using_keyring(plaintext_data, keyring)
    :param plaintext_data: plaintext data you want to encrypt
    :type: bytes
    :param keyring: Keyring to use for encryption.
    :type keyring: IKeyring
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    ciphertext_data, _ = client.encrypt(
        source=plaintext_data,
        keyring=keyring
    )

    return ciphertext_data


def decrypt_using_keyring(
    ciphertext_data: bytes,
    keyring: IKeyring
):
    """Demonstrate how to decrypt ciphertext data using an AWS KMS keyring.

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
