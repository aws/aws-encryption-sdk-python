# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance tests for the hierarchy keyring."""

# noqa pylint: disable=wrong-import-order
from typing import Dict

import aws_encryption_sdk
import boto3
from aws_cryptographic_materialproviders.keystore import KeyStore
from aws_cryptographic_materialproviders.keystore.config import KeyStoreConfig
from aws_cryptographic_materialproviders.keystore.models import KMSConfigurationKmsKeyArn
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CacheTypeDefault,
    CreateAwsKmsHierarchicalKeyringInput,
    DefaultCache,
    GetBranchKeyIdInput,
    GetBranchKeyIdOutput,
)
from aws_cryptographic_materialproviders.mpl.references import IBranchKeyIdSupplier, IKeyring

from ..utils.util import PerfTestUtils


class ExampleBranchKeyIdSupplier(IBranchKeyIdSupplier):
    """Example implementation of a branch key ID supplier."""

    branch_key_id_for_tenant_a: str
    branch_key_id_for_tenant_b: str

    def __init__(self, tenant_1_id, tenant_2_id):
        """Example constructor for a branch key ID supplier."""
        self.branch_key_id_for_tenant_a = tenant_1_id
        self.branch_key_id_for_tenant_b = tenant_2_id

    def get_branch_key_id(
        self,
        param: GetBranchKeyIdInput
    ) -> GetBranchKeyIdOutput:
        """Returns branch key ID from the tenant ID in input's encryption context."""
        encryption_context: Dict[str, str] = param.encryption_context

        if b"tenant" not in encryption_context:
            raise ValueError("EncryptionContext invalid, does not contain expected tenant key value pair.")

        tenant_key_id: str = encryption_context.get(b"tenant")
        branch_key_id: str

        if tenant_key_id == b"TenantA":
            branch_key_id = self.branch_key_id_for_tenant_a
        elif tenant_key_id == b"TenantB":
            branch_key_id = self.branch_key_id_for_tenant_b
        else:
            raise ValueError(f"Item does not contain valid tenant ID: {tenant_key_id=}")

        return GetBranchKeyIdOutput(branch_key_id=branch_key_id)


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
    branch_key_id_a: str = PerfTestUtils.DEFAULT_BRANCH_KEY_ID_A
    branch_key_id_b: str = PerfTestUtils.DEFAULT_BRANCH_KEY_ID_B

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
    """Demonstrate how to encrypt plaintext data using a hierarchy keyring.

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
        encryption_context=PerfTestUtils.DEFAULT_ENCRYPTION_CONTEXT
    )

    return ciphertext_data


def decrypt_using_keyring(
    ciphertext_data: bytes,
    keyring: IKeyring
):
    """Demonstrate how to decrypt ciphertext data using a hierarchy keyring.

    Usage: decrypt_using_keyring(ciphertext_data, keyring)
    :param ciphertext_data: ciphertext data you want to decrypt
    :type: bytes
    :param keyring: Keyring to use for decryption.
    :type keyring: IKeyring
    """
    client = aws_encryption_sdk.EncryptionSDKClient()

    decrypted_plaintext_data, _ = client.decrypt(
        source=ciphertext_data,
        keyring=keyring,
        encryption_context=PerfTestUtils.DEFAULT_ENCRYPTION_CONTEXT
    )

    return decrypted_plaintext_data
