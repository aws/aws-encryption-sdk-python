# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up an AWS KMS Key Store and Hierarchical Keyring per tenant,
where each tenant's AWS KMS key MUST be called with that tenant's AWS credentials,
without constructing a boto3 Session or KMS client per tenant.

Every tenant's AWS KMS Key Store is given:

- the tenant's ``TenantKmsClient``: a few references to that tenant's credentials
  and one ``KmsTransport`` shared by the whole process, which owns the only connection pool
- one DynamoDB client, shared by every tenant

The AWS KMS Key Store calls AWS KMS to create a Branch Key
(``GenerateDataKeyWithoutPlaintext`` and ``ReEncrypt``)
and to decrypt a Branch Key on a cache miss (``Decrypt``);
every one of those requests is signed with the tenant's credentials.

The tenant's KMS key is the isolation boundary;
a Branch Key Item is useless without ``kms:Decrypt`` on the KMS key that protects it,
so sharing the DynamoDB client does not let one tenant use another's Branch Key.

If your tenants do not require distinct KMS credentials,
one AWS KMS Key Store and a Branch Key ID Supplier is simpler;
see ``hierarchical_keyring_example.py``.

See ``multi_tenant/design.md`` for the options considered and the decisions made.

This example requires access to the DDB Table where you are storing the Branch Keys. This
table must be configured with the following primary key configuration: - Partition key is named
"partition_key" with type (S) - Sort key is named "sort_key" with type (S).

This example also requires, for each tenant, credentials with the following access on that tenant's KMS key:
- GenerateDataKeyWithoutPlaintext
- ReEncrypt
- Decrypt
"""
from typing import Dict

import boto3
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import CreateKeyInput, KMSConfigurationKmsKeyArn
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    CacheTypeDefault,
    CreateAwsKmsHierarchicalKeyringInput,
    DefaultCache,
)
from aws_cryptographic_material_providers.mpl.references import IKeyring
from botocore.credentials import Credentials

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from .multi_tenant import KmsTransport, TenantKmsClient

EXAMPLE_DATA: bytes = b"Hello World"


def _region(kms_key_arn: str) -> str:
    return kms_key_arn.split(":")[3]


def encrypt_and_decrypt_with_keyring(
    key_store_table_name: str,
    logical_key_store_name: str,
    tenant_kms_key_ids: Dict[str, str],
    tenant_credentials: Dict[str, Credentials],
    ddb_region: str = "us-west-2",
):
    """Creates a Branch Key per tenant, then encrypts and decrypts a message for each tenant.

    :param key_store_table_name: Name of the DynamoDB table backing the AWS KMS Key Store
    :param logical_key_store_name: Logical name of the AWS KMS Key Store
    :param tenant_kms_key_ids: Map of tenant name to the ARN of that tenant's KMS key
    :param tenant_credentials: Map of tenant name to that tenant's credentials
    :param ddb_region: Region of the DynamoDB table
    """
    # 1. Instantiate the encryption SDK client and the material providers once, and share them.
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # 2. Create one DynamoDB client, shared by every tenant's AWS KMS Key Store,
    #    and one transport for every tenant's KMS requests.
    ddb_client = boto3.client("dynamodb", region_name=ddb_region)
    transport = KmsTransport()

    try:
        for tenant, kms_key_id in tenant_kms_key_ids.items():
            # 3. Create a KMS client for this tenant.
            #    This is a few references, not a boto3 client; construct as many as you have tenants.
            tenant_kms_client = TenantKmsClient(
                transport=transport,
                region_name=_region(kms_key_id),
                credentials=tenant_credentials[tenant],
            )

            # 4. Create this tenant's AWS KMS Key Store.
            #    Every KMS request it makes is signed with this tenant's credentials.
            key_store: KeyStore = KeyStore(
                config=KeyStoreConfig(
                    ddb_client=ddb_client,
                    ddb_table_name=key_store_table_name,
                    logical_key_store_name=logical_key_store_name,
                    kms_client=tenant_kms_client,
                    kms_configuration=KMSConfigurationKmsKeyArn(
                        value=kms_key_id
                    ),
                )
            )

            # 5. Create a Branch Key for this tenant.
            #    This calls kms:GenerateDataKeyWithoutPlaintext and kms:ReEncrypt.
            #    Applications usually create a tenant's Branch Key once, when the tenant is onboarded,
            #    and persist the Branch Key ID.
            branch_key_id: str = key_store.create_key(input=CreateKeyInput()).branch_key_identifier

            # 6. Create this tenant's Hierarchical Keyring.
            #    Applications SHOULD cache keyrings per tenant, rather than create one per request,
            #    so that the Branch Key cache is effective.
            hierarchical_keyring: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
                input=CreateAwsKmsHierarchicalKeyringInput(
                    key_store=key_store,
                    branch_key_id=branch_key_id,
                    ttl_seconds=600,
                    cache=CacheTypeDefault(
                        value=DefaultCache(
                            entry_capacity=100
                        )
                    ),
                )
            )

            # 7. Encrypt and decrypt with the tenant's keyring.
            #    On a Branch Key cache miss, the AWS KMS Key Store calls kms:Decrypt with the tenant's credentials.
            encryption_context: Dict[str, str] = {
                "tenant": tenant,
                "encryption": "context",
                "is not": "secret",
            }
            ciphertext, _ = client.encrypt(
                source=EXAMPLE_DATA,
                keyring=hierarchical_keyring,
                encryption_context=encryption_context,
            )
            assert ciphertext != EXAMPLE_DATA, \
                "Ciphertext and plaintext data are the same. Invalid encryption"

            plaintext, _ = client.decrypt(
                source=ciphertext,
                keyring=hierarchical_keyring,
                encryption_context=encryption_context,
            )
            assert plaintext == EXAMPLE_DATA, \
                "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
    finally:
        # 8. Close the transport only when the application shuts down.
        #    It is shared by every tenant; this example owns it, and every tenant is done with it here.
        #    An application MUST NOT close it while any tenant's keyring may still use it:
        #    in-flight requests complete, but every pooled connection is dropped,
        #    so every tenant pays a new TLS handshake on its next request.
        transport.close()
