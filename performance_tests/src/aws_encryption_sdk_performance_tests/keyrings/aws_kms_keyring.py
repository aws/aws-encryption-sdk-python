# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the AWS KMS keyring."""

import aws_encryption_sdk
import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from aws_encryption_sdk import CommitmentPolicy


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
    kms_client = boto3.client('kms', region_name="us-west-2")

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
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    _, _ = client.encrypt(
        source=plaintext_data,
        keyring=keyring
    )


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
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    _, _ = client.decrypt(
        source=ciphertext_data,
        keyring=keyring
    )
