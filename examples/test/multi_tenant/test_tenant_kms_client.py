# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the per-tenant KMS client."""
# pylint: disable=redefined-outer-name,protected-access
import botocore.exceptions
import pytest
from botocore.credentials import Credentials

from ...src.multi_tenant import KmsTransport, TenantKmsClient
from ...src.multi_tenant.tenant_kms_client import METHOD_TO_API_MAPPING
from . import fake_kms

pytestmark = [pytest.mark.examples]

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
KEY_A2 = "arn:aws:kms:us-west-2:111122223333:key/a2a2a2a2-a2a2-a2a2-a2a2-a2a2a2a2a2a2"
KEY_B = "arn:aws:kms:us-west-2:444455556666:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TENANT_A = Credentials("AKIATENANTA", "secret-a", "token-a")
TENANT_B = Credentials("AKIATENANTB", "secret-b")
EC = {"tenant": "A"}


@pytest.fixture
def transport():
    return KmsTransport()


@pytest.fixture
def kms(transport):
    fake = fake_kms.install(transport)
    fake.add_key(KEY_A, TENANT_A.access_key)
    fake.add_key(KEY_A2, TENANT_A.access_key)
    fake.add_key(KEY_B, TENANT_B.access_key)
    return fake


@pytest.fixture
def client_a(transport, kms):  # pylint: disable=unused-argument
    return TenantKmsClient(transport=transport, region_name="us-west-2", credentials=TENANT_A)


@pytest.fixture
def client_b(transport, kms):  # pylint: disable=unused-argument
    return TenantKmsClient(transport=transport, region_name="us-west-2", credentials=TENANT_B)


def test_all_operations_round_trip_bytes(client_a, kms):
    generated = client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32, EncryptionContext=EC)
    assert isinstance(generated["Plaintext"], bytes) and len(generated["Plaintext"]) == 32
    assert isinstance(generated["CiphertextBlob"], bytes)
    assert generated["ResponseMetadata"]["HTTPStatusCode"] == 200

    decrypted = client_a.decrypt(CiphertextBlob=generated["CiphertextBlob"], EncryptionContext=EC, KeyId=KEY_A)
    assert decrypted["Plaintext"] == generated["Plaintext"]

    encrypted = client_a.encrypt(KeyId=KEY_A, Plaintext=b"\x00\x01data", EncryptionContext=EC)
    assert client_a.decrypt(CiphertextBlob=encrypted["CiphertextBlob"], EncryptionContext=EC)["Plaintext"] == (
        b"\x00\x01data"
    )

    without = client_a.generate_data_key_without_plaintext(KeyId=KEY_A, KeySpec="AES_256", EncryptionContext=EC)
    assert "Plaintext" not in without

    re_encrypted = client_a.re_encrypt(
        CiphertextBlob=without["CiphertextBlob"],
        SourceKeyId=KEY_A,
        SourceEncryptionContext=EC,
        DestinationKeyId=KEY_A2,
        DestinationEncryptionContext={"tenant": "A", "version": "2"},
    )
    assert re_encrypted["SourceKeyId"] == KEY_A
    assert re_encrypted["KeyId"] == KEY_A2

    assert [request["operation"] for request in kms.requests] == [
        "GenerateDataKey", "Decrypt", "Encrypt", "Decrypt", "GenerateDataKeyWithoutPlaintext", "ReEncrypt",
    ]
    assert {request["access_key"] for request in kms.requests} == {"AKIATENANTA"}


def test_each_tenant_signs_with_its_own_credentials(client_a, client_b, kms):
    client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    client_b.generate_data_key(KeyId=KEY_B, NumberOfBytes=32)
    client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    assert [request["access_key"] for request in kms.requests] == ["AKIATENANTA", "AKIATENANTB", "AKIATENANTA"]


def test_tenant_cannot_use_another_tenants_key(client_a, client_b):
    ciphertext = client_a.encrypt(KeyId=KEY_A, Plaintext=b"secret", EncryptionContext=EC)["CiphertextBlob"]
    with pytest.raises(botocore.exceptions.ClientError) as excinfo:
        client_b.decrypt(CiphertextBlob=ciphertext, EncryptionContext=EC)
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"


def test_unknown_and_missing_parameters_fail_before_any_request(client_a, kms):
    with pytest.raises(botocore.exceptions.ParamValidationError) as excinfo:
        client_a.decrypt(CiphertextBlob=b"x", aws_access_key_id="AKIAOTHER")
    assert "aws_access_key_id" in str(excinfo.value)
    with pytest.raises(botocore.exceptions.ParamValidationError) as excinfo:
        client_a.re_encrypt(CiphertextBlob=b"x")
    assert "DestinationKeyId" in str(excinfo.value)
    with pytest.raises(botocore.exceptions.ParamValidationError) as excinfo:
        client_a.encrypt(KeyId=KEY_A, Plaintext=12345)
    assert "12345" not in str(excinfo.value)
    assert not kms.requests


def test_meta_matches_what_the_mpl_and_mkps_touch(client_a):
    assert client_a.meta.region_name == "us-west-2"
    assert client_a.meta.config.user_agent_extra is None
    client_a.meta.config.user_agent_extra = "AwsCryptographicMPL/Python"
    assert set(client_a.meta.method_to_api_mapping) == set(METHOD_TO_API_MAPPING)
    for method_name in client_a.meta.method_to_api_mapping:
        assert callable(getattr(client_a, method_name))


def test_user_agent_extra_is_read_per_request(client_a, kms):
    client_a.meta.config.user_agent_extra = "AwsCryptographicMPL/Python"
    client_a.generate_data_key(KeyId=KEY_A, NumberOfBytes=32)
    assert kms.requests[0]["user_agent"].endswith(" AwsCryptographicMPL/Python")


def test_repr_never_includes_credentials(client_a):
    text = repr(client_a)
    assert "us-west-2" in text
    for secret in ("AKIATENANTA", "secret-a", "token-a"):
        assert secret not in text


@pytest.mark.parametrize("kwargs, error", [
    ({"transport": object(), "region_name": "us-west-2", "credentials": TENANT_A}, TypeError),
    ({"region_name": "evil.example.com", "credentials": TENANT_A}, ValueError),
    ({"region_name": "us-west-2", "credentials": "AKIATENANTA"}, TypeError),
])
def test_invalid_construction(transport, kwargs, error):
    kwargs.setdefault("transport", transport)
    with pytest.raises(error):
        TenantKmsClient(**kwargs)
