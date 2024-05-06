# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the Hierarchical Keyring, which establishes a key hierarchy where "branch"
keys are persisted in DynamoDb. These branch keys are used to protect your data keys, and these
branch keys are themselves protected by a KMS Key.

Establishing a key hierarchy like this has two benefits:
First, by caching the branch key material, and only calling KMS to re-establish authentication
regularly according to your configured TTL, you limit how often you need to call KMS to protect
your data. This is a performance security tradeoff, where your authentication, audit, and logging
from KMS is no longer one-to-one with every encrypt or decrypt call. Additionally, KMS Cloudtrail
cannot be used to distinguish Encrypt and Decrypt calls, and you cannot restrict who has
Encryption rights from who has Decryption rights since they both ONLY need KMS:Decrypt. However,
the benefit is that you no longer have to make a network call to KMS for every encrypt or
decrypt.

Second, this key hierarchy facilitates cryptographic isolation of a tenant's data in a
multi-tenant data store. Each tenant can have a unique Branch Key, that is only used to protect
the tenant's data. You can either statically configure a single branch key to ensure you are
restricting access to a single tenant, or you can implement an interface that selects the Branch
Key based on the Encryption Context.

This example demonstrates configuring a Hierarchical Keyring with a Branch Key ID Supplier to
encrypt and decrypt data for two separate tenants.

This example requires access to the DDB Table where you are storing the Branch Keys. This
table must be configured with the following primary key configuration: - Partition key is named
"partition_key" with type (S) - Sort key is named "sort_key" with type (S).

This example also requires using a KMS Key. You need the following access on this key: -
GenerateDataKeyWithoutPlaintext - Decrypt
"""
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

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
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
    branch_key_id_a: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier
    branch_key_id_b: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier

    # 5. Create a branch key supplier that maps the branch key id to a more readable format
    branch_key_id_supplier: IBranchKeyIdSupplier = ExampleBranchKeyIdSupplier(
        tenant_1_id=branch_key_id_a,
        tenant_2_id=branch_key_id_b,
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
    encryption_context_a: Dict[str, str] = {
        "tenant": "TenantA",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create encryption context for TenantB
    encryption_context_b: Dict[str, str] = {
        "tenant": "TenantB",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # 8. Encrypt the data with encryptionContextA & encryptionContextB
    ciphertext_a, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=hierarchical_keyring,
        encryption_context=encryption_context_a
    )
    ciphertext_b, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=hierarchical_keyring,
        encryption_context=encryption_context_b
    )

    # 9. To attest that TenantKeyB cannot decrypt a message written by TenantKeyA,
    #    let's construct more restrictive hierarchical keyrings.
    keyring_input_a: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
        key_store=keystore,
        branch_key_id=branch_key_id_a,
        ttl_seconds=600,
        cache=CacheTypeDefault(
            value=DefaultCache(
                entry_capacity=100
            )
        ),
    )

    hierarchical_keyring_a: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=keyring_input_a
    )

    keyring_input_b: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
        key_store=keystore,
        branch_key_id=branch_key_id_b,
        ttl_seconds=600,
        cache=CacheTypeDefault(
            value=DefaultCache(
                entry_capacity=100
            )
        ),
    )

    hierarchical_keyring_b: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=keyring_input_b
    )

    # 10. Demonstrate that data encrypted by one tenant's key
    #     cannot be decrypted with by a keyring specific to another tenant.

    # Keyring with tenant B's branch key cannot decrypt data encrypted with tenant A's branch key
    # This will fail and raise a AWSEncryptionSDKClientError, which we swallow ONLY for demonstration purposes.
    try:
        client.decrypt(
            source=ciphertext_a,
            keyring=hierarchical_keyring_b
        )
    except AWSEncryptionSDKClientError:
        pass

    # Keyring with tenant A's branch key cannot decrypt data encrypted with tenant B's branch key.
    # This will fail and raise a AWSEncryptionSDKClientError, which we swallow ONLY for demonstration purposes.
    try:
        client.decrypt(
            source=ciphertext_b,
            keyring=hierarchical_keyring_a
        )
    except AWSEncryptionSDKClientError:
        pass

    # 10. Demonstrate that data encrypted by one tenant's branch key can be decrypted by that tenant,
    #     and that the decrypted data matches the input data.
    plaintext_bytes_a, _ = client.decrypt(
        source=ciphertext_a,
        keyring=hierarchical_keyring_a
    )
    assert plaintext_bytes_a == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
    plaintext_bytes_b, _ = client.decrypt(
        source=ciphertext_b,
        keyring=hierarchical_keyring_b
    )
    assert plaintext_bytes_b == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
