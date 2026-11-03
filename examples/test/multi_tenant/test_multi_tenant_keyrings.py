# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests: the MPL accepts a TenantKmsClient wherever it accepts a KMS client.

If a future MPL adds a runtime isinstance(BaseClient) check, these tests fail; see design.md, 4.1.
"""
# pylint: disable=redefined-outer-name,protected-access
import pytest
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    CreateAwsKmsKeyringInput,
    CreateAwsKmsMrkDiscoveryMultiKeyringInput,
    DiscoveryFilter,
)
from botocore.credentials import Credentials

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

from ...src import multi_tenant_kms_keyring_example
from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ...src.multi_tenant_hierarchical_keyring_example import tenant_partition_id
from ...src.multi_tenant_kms_keyring_example import TenantClientSupplier
from . import fake_kms

pytestmark = [pytest.mark.examples]

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
KEY_B = "arn:aws:kms:us-east-1:444455556666:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TENANT_A = Credentials("AKIATENANTA", "secret-a")
TENANT_B = Credentials("AKIATENANTB", "secret-b")


@pytest.fixture
def transport():
    return KmsTransport()


@pytest.fixture
def kms(transport):
    fake = fake_kms.install(transport)
    fake.add_key(KEY_A, TENANT_A.access_key)
    fake.add_key(KEY_B, TENANT_B.access_key)
    return fake


def test_keyring_example_signs_every_request_with_the_owning_tenant(monkeypatch, transport, kms):
    monkeypatch.setattr(multi_tenant_kms_keyring_example, "KmsTransport", lambda: transport)

    multi_tenant_kms_keyring_example.encrypt_and_decrypt_with_keyring(
        tenant_kms_key_ids={"TenantA": KEY_A, "TenantB": KEY_B},
        tenant_credentials={"TenantA": TENANT_A, "TenantB": TENANT_B},
    )

    # FakeKms rejects any request not signed by the key's owner; also assert it saw what we expect.
    observed = [(request["operation"], request["access_key"], request["region"]) for request in kms.requests]
    assert observed == [
        ("GenerateDataKey", "AKIATENANTA", "us-west-2"),
        ("Decrypt", "AKIATENANTA", "us-west-2"),  # AWS KMS Keyring
        ("Decrypt", "AKIATENANTA", "us-west-2"),  # MRK Discovery Multi-Keyring, via TenantClientSupplier
        ("GenerateDataKey", "AKIATENANTB", "us-east-1"),
        ("Decrypt", "AKIATENANTB", "us-east-1"),
        ("Decrypt", "AKIATENANTB", "us-east-1"),
    ]
    assert all("AwsCryptographicMPL" in request["user_agent"] for request in kms.requests)


def test_discovery_keyring_cannot_decrypt_another_tenants_message(transport, kms):
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
    mat_prov = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())

    keyring_a = mat_prov.create_aws_kms_keyring(
        input=CreateAwsKmsKeyringInput(
            kms_key_id=KEY_A,
            kms_client=TenantKmsClient(transport=transport, region_name="us-west-2", credentials=TENANT_A),
        )
    )
    ciphertext, _ = client.encrypt(source=b"tenant A data", keyring=keyring_a)

    # Tenant B's discovery keyring trusts tenant A's account, but signs with tenant B's credentials.
    discovery_b = mat_prov.create_aws_kms_mrk_discovery_multi_keyring(
        input=CreateAwsKmsMrkDiscoveryMultiKeyringInput(
            regions=["us-west-2"],
            discovery_filter=DiscoveryFilter(account_ids=["111122223333"], partition="aws"),
            client_supplier=TenantClientSupplier(transport=transport, credentials=TENANT_B),
        )
    )
    with pytest.raises(AWSEncryptionSDKClientError):
        client.decrypt(source=ciphertext, keyring=discovery_b)

    assert kms.requests[-1]["operation"] == "Decrypt"
    assert kms.requests[-1]["access_key"] == "AKIATENANTB"


def test_partition_id_is_a_digest_distinct_per_tenant_and_never_the_secret():
    partition_a = tenant_partition_id(TENANT_A)
    assert partition_a == tenant_partition_id(Credentials("AKIATENANTA", "secret-a"))  # deterministic
    assert partition_a != tenant_partition_id(TENANT_B)
    assert len(partition_a) == 96 and int(partition_a, 16) >= 0  # hex encoded SHA-384
    assert TENANT_A.secret_key not in partition_a
    assert TENANT_A.access_key not in partition_a


def test_partition_id_changes_when_credentials_rotate():
    # Refreshed credentials have a new secret access key; by design, a new keyring misses the cache once.
    rotated = Credentials("AKIATENANTA", "secret-a-rotated")
    assert tenant_partition_id(TENANT_A) != tenant_partition_id(rotated)
