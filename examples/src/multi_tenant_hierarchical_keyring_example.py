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
(a cap on simultaneous fetches of Branch Keys) applies across all tenants,
and one entry capacity bounds the memory of every tenant's cached Branch Keys.
Every cache parameter is explicit and explained below;
applications SHOULD tune them to their own usage pattern.
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
"branch-key-id" with type (S) - Sort key is named "type" with type (S).

This example creates a new Branch Key per tenant every time it runs, and returns their Branch Key IDs.
Branch Keys SHOULD NOT be deleted in production: deleting a Branch Key cryptographically shreds
every message it protected. This example's test deletes them only to keep the example table from growing.

This example also requires, for each tenant, credentials with the following access on that tenant's KMS key:
- GenerateDataKeyWithoutPlaintext
- ReEncrypt
- Decrypt
"""
import hashlib

import boto3
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import CreateKeyInput, KMSConfigurationKmsKeyArn
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    CacheTypeShared,
    CacheTypeStormTracking,
    CreateAwsKmsHierarchicalKeyringInput,
    CreateCryptographicMaterialsCacheInput,
    StormTrackingCache,
    TimeUnits,
)
from aws_cryptographic_material_providers.mpl.references import IKeyring
from botocore.credentials import Credentials
from typing import Dict, Optional  # noqa pylint: disable=wrong-import-order

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
    branch_key_ids: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Creates a Branch Key per tenant, then encrypts and decrypts a message for each tenant.

    :param key_store_table_name: Name of the DynamoDB table backing the AWS KMS Key Store
    :param logical_key_store_name: Logical name of the AWS KMS Key Store
    :param tenant_kms_key_ids: Map of tenant name to the ARN of that tenant's KMS key
    :param tenant_credentials: Map of tenant name to that tenant's credentials
    :param ddb_region: Region of the DynamoDB table
    :param branch_key_ids: If given, filled in with each tenant's Branch Key ID as soon as it is created,
        so the caller can clean them up even if this function raises (optional)
    :returns: Map of tenant name to the Branch Key ID created for that tenant
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

    # 3. Create one storm tracking cache, shared by every tenant's Hierarchical Keyring.
    #    As a cached Branch Key nears expiry, one request refreshes it while the others keep using
    #    the cached entry, rather than all calling DynamoDB and KMS; and fan_out caps how many
    #    distinct Branch Keys are fetched at once. Sharing the cache applies that cap across every tenant.
    #
    #    Every parameter is set explicitly, rather than using the MPL's DefaultCache,
    #    as the defaults suit a cache per keyring; shared by every tenant, fan_out and in_flight_ttl need changing.
    #    These values are illustrative. Applications SHOULD tune every one of them to their own usage pattern:
    #    the number of tenants, how many tenants miss the cache at once, Branch Key TTLs,
    #    and DynamoDB and KMS latency.
    #
    #    Requires aws-cryptographic-material-providers 1.11.3 or later; earlier Python releases sleep
    #    sleep_milli seconds, not milliseconds, whenever fan_out is reached (MPL issue #1940).
    shared_cache = CacheTypeShared(
        value=mat_prov.create_cryptographic_materials_cache(
            input=CreateCryptographicMaterialsCacheInput(
                cache=CacheTypeStormTracking(
                    value=StormTrackingCache(
                        # Maximum Branch Keys cached, across every tenant; not per tenant.
                        # Size it for the number of tenants times the Branch Keys each has in use.
                        # 1000 is the MPL default.
                        entry_capacity=1000,
                        # Entries evicted at a time when the cache is full. The MPL default.
                        entry_pruning_tail_size=1,
                        # Begin refreshing an entry this long before it expires;
                        # until then, other requests keep using the cached entry.
                        # The MPL default; short relative to the 600 second ttl_seconds of the keyrings below.
                        grace_period=10_000,
                        # Within the grace period, at most one request per interval is sent to refresh an entry.
                        # The MPL default.
                        grace_interval=1_000,
                        # Maximum number of distinct Branch Keys being fetched at once, across every tenant.
                        # Once it is reached, a caller whose Branch Key has no cached entry blocks.
                        # The MPL default of 20 suits a cache per keyring; shared by every tenant,
                        # it would serialize a burst of tenants missing the cache at once (e.g. at startup).
                        fan_out=100,
                        # How long a fetch counts against fan_out. The keyring only marks a fetch complete
                        # when it succeeds, so a failed fetch holds its slot for this long.
                        # Lowered from the MPL default of 10 seconds, so a tenant whose fetches fail
                        # (e.g. revoked credentials) cannot hold slots the other tenants need for long.
                        # SHOULD exceed a typical DynamoDB plus KMS fetch, including retries;
                        # a fetch that takes longer may be duplicated by another request.
                        in_flight_ttl=5_000,
                        # How long a blocked caller sleeps before checking the cache again,
                        # always in milliseconds. The MPL default.
                        sleep_milli=20,
                        # The unit of grace_period, grace_interval, and in_flight_ttl.
                        # MUST be set: StormTrackingCache defaults to seconds,
                        # unlike the MPL's DefaultCache, which uses milliseconds.
                        # The MPL also requires grace_interval <= in_flight_ttl <= grace_period.
                        time_units=TimeUnits.MILLISECONDS,
                    )
                ),
            )
        )
    )

    # The Branch Key ID created for each tenant; filled in as each is created, so the caller can track them.
    if branch_key_ids is None:
        branch_key_ids = {}

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
            #    Branch Keys SHOULD NOT be deleted in production: deleting a Branch Key
            #    cryptographically shreds every message it protected. This example creates a new
            #    Branch Key per tenant on every run, so its test deletes them, to keep the table from growing.
            branch_key_id: str = key_store.create_key(input=CreateKeyInput()).branch_key_identifier
            branch_key_ids[tenant] = branch_key_id

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

    return branch_key_ids
