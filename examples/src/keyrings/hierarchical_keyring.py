# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example showing basic encryption and decryption of a value already in memory."""
import sys

import boto3
from aws_cryptographic_materialproviders.keystore.client import KeyStore
from aws_cryptographic_materialproviders.keystore.config import KeyStoreConfig
from aws_cryptographic_materialproviders.keystore.models import CreateKeyInput, KMSConfigurationKmsKeyArn
from aws_cryptographic_materialproviders.mpl.client import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CacheTypeDefault,
    CreateAwsKmsHierarchicalKeyringInput,
    DefaultCache,
    GetBranchKeyIdInput,
    GetBranchKeyIdOutput,
)
from aws_cryptographic_materialproviders.mpl.references import IBranchKeyIdSupplier, IKeyring

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

module_root_dir = '/'.join(__file__.split("/")[:-1])

sys.path.append(module_root_dir)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    key_store_table_name: str,
    logical_key_store_name: str,
    kms_key_id: str
):
    """Creates a hierarchical keyring using the provided resources, then encrypts and decrypts a string with it."""

    # 1. Instantiate the encryption SDK client.
    #    This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
    #    which enforces that this client only encrypts using committing algorithm suites and enforces
    #    that this client will only decrypt encrypted messages that were created with a committing
    #    algorithm suite.
    #    This is the default commitment policy if you were to build the client as
    #    `client = aws_encryption_sdk.EncryptionSDKClient()`.

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    # 2. Create boto3 clients for DynamoDB and KMS.
    ddb_client = boto3.client('dynamodb')
    kms_client = boto3.client('kms')

    # 3. Configure your KeyStore resource.
    #    This SHOULD be the same configuration that you used
    #    to initially create and populate your KeyStore.
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

    # 4. Call CreateKey to create two new active branch keys
    branch_key_id_A: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier
    branch_key_id_B: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier

    class ExampleBranchKeyIdSupplier(IBranchKeyIdSupplier):
        branch_key_id_for_tenant_A: str
        branch_key_id_for_tenant_B: str

        def __init__(self, tenant_1_id, tenant_2_id):
            self.branch_key_id_for_tenant_A = tenant_1_id
            self.branch_key_id_for_tenant_B = tenant_2_id

        def get_branch_key_id(
            self,
            input: GetBranchKeyIdInput
        ) -> GetBranchKeyIdOutput:
            encryption_context: dict[str, str] = input.encryption_context

            if b"tenant" not in encryption_context:
                raise ValueError("EncryptionContext invalid, does not contain expected tenant key value pair.")

            tenant_key_id: str = encryption_context.get(b"tenant")
            branch_key_id: str

            if tenant_key_id == b"TenantA":
                branch_key_id = self.branch_key_id_for_tenant_A
            elif tenant_key_id == b"TenantB":
                branch_key_id = self.branch_key_id_for_tenant_B
            else:
                raise ValueError(f"Item does not contain valid tenant ID: {tenant_key_id=}")

            return GetBranchKeyIdOutput(branch_key_id=branch_key_id)

    # 5. Create a branch key supplier that maps the branch key id to a more readable format
    branch_key_id_supplier: IBranchKeyIdSupplier = ExampleBranchKeyIdSupplier(
        tenant_1_id=branch_key_id_A,
        tenant_2_id=branch_key_id_B,
    )

    # 6. Create the Hierarchical Keyring.
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

    hierarchical_keyring: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=keyring_input
    )

    # The Branch Key Id supplier uses the encryption context to determine which branch key id will
    # be used to encrypt data.
    # Create encryption context for TenantA
    encryption_context_A: dict[str, str] = {
        "tenant": "TenantA",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create encryption context for TenantB
    encryption_context_B: dict[str, str] = {
        "tenant": "TenantB",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Encrypt the data for encryptionContextA & encryptionContextB
    ciphertext_A, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=hierarchical_keyring,
        encryption_context=encryption_context_A
    )
    ciphertext_B, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=hierarchical_keyring,
        encryption_context=encryption_context_B
    )

    # To attest that TenantKeyB cannot decrypt a message written by TenantKeyA
    # let's construct more restrictive hierarchical keyrings.
    keyring_input_A: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
        key_store=keystore,
        branch_key_id=branch_key_id_A,
        ttl_seconds=600,
        cache=CacheTypeDefault(
            value=DefaultCache(
                entry_capacity=100
            )
        ),
    )

    hierarchical_keyring_A: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=keyring_input_A
    )

    keyring_input_B: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
        key_store=keystore,
        branch_key_id=branch_key_id_B,
        ttl_seconds=600,
        cache=CacheTypeDefault(
            value=DefaultCache(
                entry_capacity=100
            )
        ),
    )

    hierarchical_keyring_B: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=keyring_input_B
    )

    # TODO: Run the decrypt, get expected exception type
    # This should fail
    try:
        client.decrypt(
            source=ciphertext_A,
            keyring=hierarchical_keyring_B
        )
    except AWSEncryptionSDKClientError:
        pass

    # # This should fail
    try:
        client.decrypt(
            source=ciphertext_B,
            keyring=hierarchical_keyring_A
        )
    except AWSEncryptionSDKClientError:
        pass

    # These should succeed
    plaintext_bytes_A, _ = client.decrypt(
        source=ciphertext_A,
        keyring=hierarchical_keyring_A
    )
    assert plaintext_bytes_A == EXAMPLE_DATA
    plaintext_bytes_B, _ = client.decrypt(
        source=ciphertext_B,
        keyring=hierarchical_keyring_B
    )
    assert plaintext_bytes_B == EXAMPLE_DATA

# Also, a thread-safe example ig
