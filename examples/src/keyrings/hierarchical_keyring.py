# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example showing basic encryption and decryption of a value already in memory."""
import sys

import boto3
# Ignore missing MPL for pylint, but the MPL is required for this example
# noqa pylint: disable=import-error
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
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

from .example_branch_key_id_supplier import ExampleBranchKeyIdSupplier

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
    ddb_client = boto3.client('dynamodb', region_name="us-west-2")
    kms_client = boto3.client('kms', region_name="us-west-2")

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

    # 7. Create encryption context for both tenants.
    #    The Branch Key Id supplier uses the encryption context to determine which branch key id will
    #    be used to encrypt data.

    # Create encryption context for TenantA
    encryption_context_A: Dict[str, str] = {
        "tenant": "TenantA",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create encryption context for TenantB
    encryption_context_B: Dict[str, str] = {
        "tenant": "TenantB",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # 8. Encrypt the data for encryptionContextA & encryptionContextB
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

    # 9. To attest that TenantKeyB cannot decrypt a message written by TenantKeyA,
    #    let's construct more restrictive hierarchical keyrings.
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

    # 10. Demonstrate that data encrypted by one tenant's key
    #     cannot be decrypted with by a keyring specific to another tenant.

    # Keyring with tenant B's branch key cannot decrypt data encrypted with tenant A's branch key
    # This will fail and raise a AWSEncryptionSDKClientError, which we swallow ONLY for demonstration purposes.
    try:
        client.decrypt(
            source=ciphertext_A,
            keyring=hierarchical_keyring_B
        )
    except AWSEncryptionSDKClientError:
        pass

    # Keyring with tenant A's branch key cannot decrypt data encrypted with tenant B's branch key.
    # This will fail and raise a AWSEncryptionSDKClientError, which we swallow ONLY for demonstration purposes.
    try:
        client.decrypt(
            source=ciphertext_B,
            keyring=hierarchical_keyring_A
        )
    except AWSEncryptionSDKClientError:
        pass

    # 10. Demonstrate that data encrypted by one tenant's branch key can be decrypted by that tenant,
    #     and that the decrypted data matches the input data.
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
