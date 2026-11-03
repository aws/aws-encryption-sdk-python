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

Every tenant's Hierarchical Keyring is given one cache, shared by every tenant.
The cache is a storm tracking cache, so its thundering herd mitigation
(a cap on simultaneous refreshes of cached Branch Keys) applies across all tenants,
and one entry capacity bounds the memory of every tenant's cached Branch Keys.
Each keyring's Partition ID, derived from its tenant's credentials,
additionally isolates tenants within the shared cache.

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
import hashlib
from typing import Dict

import boto3
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import CreateKeyInput, KMSConfigurationKmsKeyArn
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    CacheTypeDefault,
    CacheTypeShared,
    CreateAwsKmsHierarchicalKeyringInput,
    CreateCryptographicMaterialsCacheInput,
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


def tenant_partition_id(credentials: Credentials) -> str:
    """Derives a shared cache Partition ID from a tenant's credentials.

    The Partition ID is the SHA-384 digest of the tenant's secret access key:

    - It is distinct for every set of credentials, so tenants are isolated within the shared cache,
      in addition to being isolated by their Branch Key IDs.
    - It is not the secret. A Hierarchical Keyring keeps its Partition ID, unhashed, for its lifetime;
      a digest of a high entropy secret discloses nothing useful.
    - It changes when refreshable credentials rotate. A keyring created after a refresh
      does not share cache entries with one created before it, and will miss the cache once;
      this ties a tenant's cache usage to the lifetime of its credentials.

    :param credentials: The tenant's credentials
    :returns: A hex encoded SHA-384 digest
    """
    secret_key = credentials.get_frozen_credentials().secret_key
    return hashlib.sha384(secret_key.encode("utf-8")).hexdigest()


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

    # 3. Create one cache, shared by every tenant's Hierarchical Keyring.
    #    The Default cache is a storm tracking cache: as a cached Branch Key nears expiry,
    #    one request refreshes it while the others keep using the cached entry,
    #    rather than all calling DynamoDB and KMS; and its fan out caps how many refreshes run at once.
    #    Sharing the cache applies that cap across every tenant, rather than per tenant.
    #    Size entry_capacity for every tenant's Branch Keys, not one tenant's.
    shared_cache = CacheTypeShared(
        value=mat_prov.create_cryptographic_materials_cache(
            input=CreateCryptographicMaterialsCacheInput(
                cache=CacheTypeDefault(
                    value=DefaultCache(
                        entry_capacity=1000
                    )
                ),
            )
        )
    )

    try:
        for tenant, kms_key_id in tenant_kms_key_ids.items():
            # 4. Create a KMS client for this tenant.
            #    This is a few references, not a boto3 client; construct as many as you have tenants.
            tenant_kms_client = TenantKmsClient(
                transport=transport,
                region_name=_region(kms_key_id),
                credentials=tenant_credentials[tenant],
            )

            # 5. Create this tenant's AWS KMS Key Store.
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

            # 6. Create a Branch Key for this tenant.
            #    This calls kms:GenerateDataKeyWithoutPlaintext and kms:ReEncrypt.
            #    Applications usually create a tenant's Branch Key once, when the tenant is onboarded,
            #    and persist the Branch Key ID.
            branch_key_id: str = key_store.create_key(input=CreateKeyInput()).branch_key_identifier

            # 7. Create this tenant's Hierarchical Keyring, on the shared cache.
            #    Keyrings share cache entries only if their Partition ID, Logical Key Store Name,
            #    and Branch Key ID are all the same. Every tenant's AWS KMS Key Store has the same
            #    Logical Key Store Name, as they are instances of the same physical Key Store;
            #    the Partition ID, derived from the tenant's credentials, keeps tenants apart
            #    even if a Branch Key ID were ever reused or misconfigured.
            #    Applications SHOULD cache keyrings per tenant, rather than create one per request.
            hierarchical_keyring: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
                input=CreateAwsKmsHierarchicalKeyringInput(
                    key_store=key_store,
                    branch_key_id=branch_key_id,
                    ttl_seconds=600,
                    cache=shared_cache,
                    partition_id=tenant_partition_id(tenant_credentials[tenant]),
                )
            )

            # 8. Encrypt and decrypt with the tenant's keyring.
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
        # 9. Close the transport and the DynamoDB client only when the application shuts down.
        #    Both are shared by every tenant; this example owns them, and every tenant is done with them here.
        #    An application MUST NOT close either while any tenant's keyring may still use it:
        #    in-flight requests complete, but every pooled connection is dropped,
        #    so every tenant pays a new TLS handshake on its next request.
        transport.close()
        ddb_client.close()
