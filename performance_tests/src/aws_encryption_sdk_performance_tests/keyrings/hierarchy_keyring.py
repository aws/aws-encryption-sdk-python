# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the hierarchy keyring."""

import aws_encryption_sdk
import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring

from aws_cryptographic_materialproviders.keystore import KeyStore
from aws_cryptographic_materialproviders.keystore.config import KeyStoreConfig
from aws_cryptographic_materialproviders.keystore.models import CreateKeyInput, KMSConfigurationKmsKeyArn
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CacheTypeDefault,
    CreateAwsKmsHierarchicalKeyringInput,
    DefaultCache,
)
from aws_cryptographic_materialproviders.mpl.references import IBranchKeyIdSupplier, IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

from .branch_key_id_supplier_example import ExampleBranchKeyIdSupplier


def create_keyring(
    key_store_table_name: str,
    logical_key_store_name: str,
    kms_key_id: str
):
    """Demonstrate how to create a hierarchy keyring.

    Usage: create_keyring(key_store_table_name, logical_key_store_name, kms_key_id)
    :param key_store_table_name: Name of the KeyStore DynamoDB table.
    :type key_store_table_name: string
    :param logical_key_store_name: Logical name of the KeyStore.
    :type logical_key_store_name: string
    :param kms_key_id: KMS Key identifier for the KMS key you want to use.
    :type kms_key_id: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    # Create boto3 clients for DynamoDB and KMS.
    ddb_client = boto3.client('dynamodb', region_name="us-west-2")
    kms_client = boto3.client('kms', region_name="us-west-2")

    # Configure your KeyStore resource.
    # This SHOULD be the same configuration that you used
    # to initially create and populate your KeyStore.
    keystore: KeyStore = KeyStore(
        config=KeyStoreConfig(
            ddb_client=ddb_client,
            ddb_table_name=key_store_table_name,
            logical_key_store_name=logical_key_store_name,
            kms_client=kms_client,
            kms_configuration=KMSConfigurationKmsKeyArn(
                value=kms_key_id
            ),
        )
    )

    # Call CreateKey to create two new active branch keys
    branch_key_id_a: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier
    branch_key_id_b: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier

    # Create a branch key supplier that maps the branch key id to a more readable format
    branch_key_id_supplier: IBranchKeyIdSupplier = ExampleBranchKeyIdSupplier(
        tenant_1_id=branch_key_id_a,
        tenant_2_id=branch_key_id_b,
    )

    # Create the Hierarchical Keyring.
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
        key_store=keystore,
        branch_key_id_supplier=branch_key_id_supplier,
        ttl_seconds=600,
        cache=CacheTypeDefault(
            value=DefaultCache(
                entry_capacity=100
            )
        ),
    )

    keyring: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
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
