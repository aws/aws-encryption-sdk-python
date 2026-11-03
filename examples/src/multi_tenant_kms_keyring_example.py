# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example encrypts and decrypts data for several tenants,
where each tenant's AWS KMS key MUST be called with that tenant's AWS credentials,
without constructing a boto3 Session or KMS client per tenant.

boto3 binds credentials to a client at construction, and every boto3 client owns its own
connection pool; at hundreds or thousands of tenants, those clients are a significant cost.
Instead, this example constructs:

- one ``KmsTransport`` for the whole process, which owns the only connection pool
- one ``TenantKmsClient`` per tenant, which holds that tenant's credentials and nothing heavy

A ``TenantKmsClient`` is accepted anywhere the AWS Cryptographic Material Providers Library
accepts a KMS client. This example uses it with:

1. an AWS KMS Keyring, to encrypt and decrypt
2. a ``ClientSupplier``, so an AWS KMS MRK Discovery Multi-Keyring can decrypt with the tenant's credentials

See ``multi_tenant/design.md`` for the options considered and the decisions made.

This example requires, for each tenant, credentials with the following access on that tenant's KMS key:
- GenerateDataKey
- Decrypt
"""
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    CreateAwsKmsKeyringInput,
    CreateAwsKmsMrkDiscoveryMultiKeyringInput,
    DiscoveryFilter,
    GetClientInput,
)
from aws_cryptographic_material_providers.mpl.references import IClientSupplier, IKeyring
from botocore.credentials import Credentials
from typing import Dict, Optional  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

from .multi_tenant import KmsTransport, TenantKmsClient

EXAMPLE_DATA: bytes = b"Hello World"


class TenantClientSupplier(IClientSupplier):
    """Supplies a ``TenantKmsClient`` for any region, all bound to one tenant's credentials.

    Multi-region and discovery keyrings ask a ClientSupplier for a client per region at runtime;
    this one constructs them over the shared transport and keeps them.
    """

    def __init__(
        self,
        transport: KmsTransport,
        credentials: Credentials,
        endpoint_urls: Optional[Dict[str, str]] = None,
    ):
        """Stores the shared transport and the tenant's credentials."""
        self._transport = transport
        self._credentials = credentials
        self._endpoint_urls = endpoint_urls or {}
        self._clients: Dict[str, TenantKmsClient] = {}

    def get_client(self, param: GetClientInput) -> TenantKmsClient:  # type: ignore[override]
        """Returns this tenant's client for ``param.region``."""
        region = param.region
        if region not in self._clients:
            # TenantKmsClient validates the region; discovery keyrings take it from the ciphertext.
            self._clients[region] = TenantKmsClient(
                transport=self._transport,
                region_name=region,
                credentials=self._credentials,
                endpoint_url=self._endpoint_urls.get(region),
            )
        return self._clients[region]


def _account_id(kms_key_arn: str) -> str:
    return kms_key_arn.split(":")[4]


def _region(kms_key_arn: str) -> str:
    return kms_key_arn.split(":")[3]


def encrypt_and_decrypt_with_keyring(
    tenant_kms_key_ids: Dict[str, str],
    tenant_credentials: Dict[str, Credentials],
):
    """Encrypts and decrypts a message for each tenant, with that tenant's KMS key and credentials.

    :param tenant_kms_key_ids: Map of tenant name to the ARN of that tenant's KMS key
    :param tenant_credentials: Map of tenant name to that tenant's credentials
    """
    # 1. Instantiate the encryption SDK client and the material providers once, and share them.
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # 2. Create one transport for the whole process.
    #    It owns the only connection pool; every tenant's KMS requests are sent over it.
    transport = KmsTransport()

    try:
        for tenant, kms_key_id in tenant_kms_key_ids.items():
            credentials = tenant_credentials[tenant]

            # 3. Create a KMS client for this tenant.
            #    This is a few references, not a boto3 client; construct as many as you have tenants.
            tenant_kms_client = TenantKmsClient(
                transport=transport,
                region_name=_region(kms_key_id),
                credentials=credentials,
            )

            # 4. Create an AWS KMS Keyring for this tenant, exactly as you would with a boto3 client.
            #    Applications SHOULD cache keyrings per tenant, rather than create one per request.
            kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
                input=CreateAwsKmsKeyringInput(
                    kms_key_id=kms_key_id,
                    kms_client=tenant_kms_client,
                )
            )

            # 5. Encrypt with the tenant's keyring.
            #    The tenant is in the encryption context, which is authenticated but not secret.
            encryption_context: Dict[str, str] = {
                "tenant": tenant,
                "encryption": "context",
                "is not": "secret",
            }
            ciphertext, _ = client.encrypt(
                source=EXAMPLE_DATA,
                keyring=kms_keyring,
                encryption_context=encryption_context,
            )
            assert ciphertext != EXAMPLE_DATA, \
                "Ciphertext and plaintext data are the same. Invalid encryption"

            # 6. Decrypt with the same keyring.
            plaintext, _ = client.decrypt(
                source=ciphertext,
                keyring=kms_keyring,
                encryption_context=encryption_context,
            )
            assert plaintext == EXAMPLE_DATA, \
                "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

            # 7. Decrypt with an MRK Discovery Multi-Keyring.
            #    Discovery keyrings learn the KMS key from the message, and ask the ClientSupplier
            #    for a client in that key's region; the TenantClientSupplier answers with this
            #    tenant's credentials. The discovery filter restricts decryption to the tenant's account.
            discovery_keyring: IKeyring = mat_prov.create_aws_kms_mrk_discovery_multi_keyring(
                input=CreateAwsKmsMrkDiscoveryMultiKeyringInput(
                    regions=[_region(kms_key_id)],
                    discovery_filter=DiscoveryFilter(
                        account_ids=[_account_id(kms_key_id)],
                        partition="aws",
                    ),
                    client_supplier=TenantClientSupplier(transport=transport, credentials=credentials),
                )
            )
            discovered_plaintext, _ = client.decrypt(
                source=ciphertext,
                keyring=discovery_keyring,
                encryption_context=encryption_context,
            )
            assert discovered_plaintext == EXAMPLE_DATA, \
                "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
    finally:
        # 8. Close the transport only when the application shuts down.
        #    It is shared by every tenant; this example owns it, and every tenant is done with it here.
        #    An application MUST NOT close it while any tenant's keyring may still use it:
        #    in-flight requests complete, but every pooled connection is dropped,
        #    so every tenant pays a new TLS handshake on its next request.
        transport.close()
