# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the multi-tenant KMS Master Key Providers example."""
# pylint: disable=redefined-outer-name,protected-access
import botocore.exceptions
import botocore.session
import pytest
import urllib3
from botocore.credentials import Credentials

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import DecryptKeyError, GenerateKeyError
from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

from ...src.legacy import multi_tenant_kms_master_key_provider as example
from ...src.legacy.multi_tenant_kms_master_key_provider import (
    TenantDiscoveryAwsKmsMasterKeyProvider,
    TenantMRKAwareDiscoveryAwsKmsMasterKeyProvider,
    TenantMRKAwareStrictAwsKmsMasterKeyProvider,
    TenantStrictAwsKmsMasterKeyProvider,
)
from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ..multi_tenant import fake_kms

pytestmark = [pytest.mark.examples]

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
MRK_A = "arn:aws:kms:us-west-2:111122223333:key/mrk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MRK_A_EAST = "arn:aws:kms:us-east-1:111122223333:key/mrk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
KEY_B = "arn:aws:kms:us-east-1:444455556666:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TENANT_A = Credentials("AKIATENANTA", "secret-a")
TENANT_B = Credentials("AKIATENANTB", "secret-b")


@pytest.fixture
def transport():
    return KmsTransport()


@pytest.fixture
def kms(transport):
    fake = fake_kms.install(transport)
    for key in (KEY_A, MRK_A, MRK_A_EAST):
        fake.add_key(key, TENANT_A.access_key)
    fake.add_key(KEY_B, TENANT_B.access_key)
    return fake


@pytest.fixture
def session():
    return botocore.session.Session()


@pytest.fixture
def esdk():
    return aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)


def test_example_signs_every_request_with_the_owning_tenant(monkeypatch, transport, kms):
    monkeypatch.setattr(example, "KmsTransport", lambda: transport)

    example.encrypt_decrypt(
        tenant_key_arns={"TenantA": KEY_A, "TenantB": KEY_B},
        tenant_credentials={"TenantA": TENANT_A, "TenantB": TENANT_B},
        source_plaintext=b"Hello World",
    )

    observed = [(request["operation"], request["access_key"], request["region"]) for request in kms.requests]
    assert observed == [
        ("GenerateDataKey", "AKIATENANTA", "us-west-2"),
        ("Decrypt", "AKIATENANTA", "us-west-2"),
        ("GenerateDataKey", "AKIATENANTB", "us-east-1"),
        ("Decrypt", "AKIATENANTB", "us-east-1"),
    ]
    assert all("AwsEncryptionSdkPython/" in request["user_agent"] for request in kms.requests)


@pytest.mark.parametrize("provider_class, key", [
    (TenantStrictAwsKmsMasterKeyProvider, KEY_A),
    (TenantMRKAwareStrictAwsKmsMasterKeyProvider, MRK_A),
])
def test_strict_providers_use_tenant_kms_clients(transport, kms, session, esdk, provider_class, key):
    provider = provider_class(key_ids=[key], transport=transport, credentials=TENANT_A, botocore_session=session)
    ciphertext, _ = esdk.encrypt(source=b"data", key_provider=provider)
    plaintext, _ = esdk.decrypt(source=ciphertext, key_provider=provider)
    assert plaintext == b"data"
    assert all(isinstance(client, TenantKmsClient) for client in provider._regional_clients.values())
    assert {request["access_key"] for request in kms.requests} == {"AKIATENANTA"}


@pytest.mark.parametrize("provider_class, kwargs", [
    (TenantDiscoveryAwsKmsMasterKeyProvider, {}),
    (TenantMRKAwareDiscoveryAwsKmsMasterKeyProvider, {"discovery_region": "us-west-2"}),
])
def test_discovery_providers_enforce_tenant_credentials(transport, kms, session, esdk, provider_class, kwargs):
    encrypt_a = TenantStrictAwsKmsMasterKeyProvider(
        key_ids=[KEY_A], transport=transport, credentials=TENANT_A, botocore_session=session
    )
    ciphertext, _ = esdk.encrypt(source=b"tenant A data", key_provider=encrypt_a)

    discovery_filter = DiscoveryFilter(account_ids=["111122223333"], partition="aws")
    discovery_a = provider_class(
        transport=transport, credentials=TENANT_A, botocore_session=session, discovery_filter=discovery_filter, **kwargs
    )
    plaintext, _ = esdk.decrypt(source=ciphertext, key_provider=discovery_a)
    assert plaintext == b"tenant A data"

    # Tenant B's provider trusts tenant A's account, but signs with tenant B's credentials.
    discovery_b = provider_class(
        transport=transport, credentials=TENANT_B, botocore_session=session, discovery_filter=discovery_filter, **kwargs
    )
    with pytest.raises(DecryptKeyError):
        esdk.decrypt(source=ciphertext, key_provider=discovery_b)
    assert kms.requests[-1]["access_key"] == "AKIATENANTB"


def test_mrk_discovery_provider_decrypts_in_the_discovery_region(transport, kms, session, esdk):
    encrypt_a = TenantMRKAwareStrictAwsKmsMasterKeyProvider(
        key_ids=[MRK_A_EAST], transport=transport, credentials=TENANT_A, botocore_session=session
    )
    ciphertext, _ = esdk.encrypt(source=b"replicated", key_provider=encrypt_a)

    discovery_a = TenantMRKAwareDiscoveryAwsKmsMasterKeyProvider(
        transport=transport,
        credentials=TENANT_A,
        botocore_session=session,
        discovery_filter=DiscoveryFilter(account_ids=["111122223333"], partition="aws"),
        discovery_region="us-west-2",
    )
    plaintext, _ = esdk.decrypt(source=ciphertext, key_provider=discovery_a)
    assert plaintext == b"replicated"
    assert kms.requests[-1]["operation"] == "Decrypt"
    assert kms.requests[-1]["region"] == "us-west-2"
    assert kms.requests[-1]["body"]["KeyId"] == MRK_A


def test_tenant_cannot_use_another_tenants_key(transport, kms, session, esdk):
    # Misconfigured: tenant B's credentials, tenant A's KMS key. KMS, not the provider, refuses.
    provider = TenantStrictAwsKmsMasterKeyProvider(
        key_ids=[KEY_A], transport=transport, credentials=TENANT_B, botocore_session=session
    )
    with pytest.raises(GenerateKeyError):
        esdk.encrypt(source=b"data", key_provider=provider)
    assert kms.requests[-1]["access_key"] == "AKIATENANTB"


def test_botocore_error_evicts_regional_client(transport, kms, session):
    provider = TenantStrictAwsKmsMasterKeyProvider(
        key_ids=[KEY_A], transport=transport, credentials=TENANT_A, botocore_session=session
    )
    client = provider._regional_clients["us-west-2"]
    kms.scripted = [urllib3.exceptions.NewConnectionError(None, "refused")] * 3
    with pytest.raises(botocore.exceptions.EndpointConnectionError):
        client.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    assert "us-west-2" not in provider._regional_clients


def test_endpoint_urls(transport, kms, session, esdk):
    provider = TenantStrictAwsKmsMasterKeyProvider(
        key_ids=[KEY_A],
        transport=transport,
        credentials=TENANT_A,
        botocore_session=session,
        endpoint_urls={"us-west-2": "https://vpce-123.kms.us-west-2.vpce.amazonaws.com"},
    )
    esdk.encrypt(source=b"data", key_provider=provider)
    assert kms.requests[0]["url"] == "https://vpce-123.kms.us-west-2.vpce.amazonaws.com"


@pytest.mark.parametrize("missing", ["transport", "credentials"])
def test_transport_and_credentials_are_required(transport, session, missing):
    kwargs = {"key_ids": [KEY_A], "transport": transport, "credentials": TENANT_A, "botocore_session": session}
    del kwargs[missing]
    with pytest.raises(TypeError):
        TenantStrictAwsKmsMasterKeyProvider(**kwargs)
