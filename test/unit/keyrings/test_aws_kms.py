# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for ``aws_encryption_sdk.keyrings.aws_kms``."""
import pytest

from aws_encryption_sdk.keyrings.aws_kms import (
    KmsKeyring,
    _AwsKmsDiscoveryKeyring,
    _AwsKmsSingleCmkKeyring,
    _region_from_key_id,
)
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import DefaultClientSupplier
from aws_encryption_sdk.keyrings.multi import MultiKeyring

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize(
    "kwargs",
    (
        pytest.param(dict(client_supplier=None), id="client_supplier is invalid"),
        pytest.param(dict(generator_key_id=5), id="generator_id is invalid"),
        pytest.param(dict(key_ids=("foo", 5)), id="key_ids contains invalid values"),
        pytest.param(dict(key_ids="some stuff"), id="key_ids is a string"),
        pytest.param(dict(grant_tokens=("foo", 5)), id="grant_tokens contains invalid values"),
        pytest.param(dict(grant_tokens="some stuff"), id="grant_tokens is a string"),
        pytest.param(dict(generator_key_id="foo", is_discovery=True), id="generator and discovery"),
        pytest.param(dict(key_ids=("foo",), is_discovery=True), id="key_ids and discovery"),
        pytest.param(dict(), id="nothing"),
    ),
)
def test_kms_keyring_invalid_parameters(kwargs):
    with pytest.raises(TypeError):
        KmsKeyring(**kwargs)


def test_kms_keyring_builds_correct_inner_keyring_multikeyring():
    generator_id = "foo"
    child_id_1 = "bar"
    child_id_2 = "baz"
    grants = ("asdf", "fdsa")
    supplier = DefaultClientSupplier()

    test = KmsKeyring(
        generator_key_id=generator_id, key_ids=(child_id_1, child_id_2), grant_tokens=grants, client_supplier=supplier,
    )

    # We specified a generator and child IDs, so the inner keyring MUST be a multikeyring
    assert isinstance(test._inner_keyring, MultiKeyring)

    # Verify that the generator is configured correctly
    assert isinstance(test._inner_keyring.generator, _AwsKmsSingleCmkKeyring)
    assert test._inner_keyring.generator._key_id == generator_id
    assert test._inner_keyring.generator._grant_tokens == grants
    assert test._inner_keyring.generator._client_supplier is supplier

    # We specified two child IDs, so there MUST be exactly two children
    assert len(test._inner_keyring.children) == 2

    # Verify that the first child is configured correctly
    assert isinstance(test._inner_keyring.children[0], _AwsKmsSingleCmkKeyring)
    assert test._inner_keyring.children[0]._key_id == child_id_1
    assert test._inner_keyring.children[0]._grant_tokens == grants
    assert test._inner_keyring.children[0]._client_supplier is supplier

    # Verify that the second child is configured correctly
    assert isinstance(test._inner_keyring.children[1], _AwsKmsSingleCmkKeyring)
    assert test._inner_keyring.children[1]._key_id == child_id_2
    assert test._inner_keyring.children[1]._grant_tokens == grants
    assert test._inner_keyring.children[1]._client_supplier is supplier


def test_kms_keyring_builds_correct_inner_keyring_multikeyring_no_generator():
    test = KmsKeyring(key_ids=("bar", "baz"))

    # We specified child IDs, so the inner keyring MUST be a multikeyring
    assert isinstance(test._inner_keyring, MultiKeyring)

    # We did not specify a generator ID, so the generator MUST NOT be set
    assert test._inner_keyring.generator is None

    # We specified two child IDs, so there MUST be exactly two children
    assert len(test._inner_keyring.children) == 2


def test_kms_keyring_builds_correct_inner_keyring_multikeyring_no_children():
    test = KmsKeyring(generator_key_id="foo")

    # We specified a generator ID, so the inner keyring MUST be a multikeyring
    assert isinstance(test._inner_keyring, MultiKeyring)

    # We specified a generator ID, so the generator MUST be set
    assert test._inner_keyring.generator is not None

    # We did not specify any child IDs, so the multikeyring MUST NOT contain any children
    assert len(test._inner_keyring.children) == 0


def test_kms_keyring_builds_correct_inner_keyring_discovery():
    grants = ("asdf", "fdas")
    supplier = DefaultClientSupplier()

    test = KmsKeyring(is_discovery=True, grant_tokens=grants, client_supplier=supplier)

    # We specified neither a generator nor children, so the inner keyring MUST be a discovery keyring
    assert isinstance(test._inner_keyring, _AwsKmsDiscoveryKeyring)

    # Verify that the discovery keyring is configured correctly
    assert test._inner_keyring._grant_tokens == grants
    assert test._inner_keyring._client_supplier is supplier


def test_kms_keyring_inner_keyring_on_encrypt(mocker):
    mock_keyring = mocker.Mock()

    keyring = KmsKeyring(is_discovery=True)
    keyring._inner_keyring = mock_keyring

    test = keyring.on_encrypt(encryption_materials=mocker.sentinel.encryption_materials)

    # on_encrypt MUST be a straight passthrough to the inner keyring
    assert mock_keyring.on_encrypt.called_once_with(encryption_materials=mocker.sentinel.encryption_materials)
    assert test is mock_keyring.on_encrypt.return_value


def test_kms_keyring_inner_keyring_on_decrypt(mocker):
    mock_keyring = mocker.Mock()

    keyring = KmsKeyring(is_discovery=True)
    keyring._inner_keyring = mock_keyring

    test = keyring.on_decrypt(
        decryption_materials=mocker.sentinel.decryption_materials,
        encrypted_data_keys=mocker.sentinel.encrypted_data_keys,
    )

    # on_decrypt MUST be a straight passthrough to the inner keyring
    assert mock_keyring.on_decrypt.called_once_with(
        decryption_materials=mocker.sentinel.decryption_materials,
        encrypted_data_keys=mocker.sentinel.encrypted_data_keys,
    )
    assert test is mock_keyring.on_decrypt.return_value


@pytest.mark.parametrize(
    "kwargs",
    (
        pytest.param(dict(key_id=None, client_supplier=DefaultClientSupplier()), id="key_id is invalid"),
        pytest.param(dict(key_id="foo", client_supplier=None), id="client_supplier is invalid"),
        pytest.param(
            dict(key_id="foo", client_supplier=DefaultClientSupplier(), grant_tokens=("bar", 5)),
            id="grant_tokens contains invalid values",
        ),
        pytest.param(
            dict(key_id="foo", client_supplier=DefaultClientSupplier(), grant_tokens="some stuff"),
            id="grant_tokens is a string",
        ),
    ),
)
def test_aws_kms_single_cmk_keyring_invalid_parameters(kwargs):
    with pytest.raises(TypeError):
        _AwsKmsSingleCmkKeyring(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    (
        pytest.param(dict(client_supplier=None), id="client_supplier is invalid"),
        pytest.param(
            dict(client_supplier=DefaultClientSupplier(), grant_tokens=("bar", 5)),
            id="grant_tokens contains invalid values",
        ),
        pytest.param(
            dict(client_supplier=DefaultClientSupplier(), grant_tokens="some stuff"), id="grant_tokens is a string",
        ),
    ),
)
def test_aws_kms_discovery_keyring_invalid_parameters(kwargs):
    with pytest.raises(TypeError):
        _AwsKmsDiscoveryKeyring(**kwargs)


@pytest.mark.parametrize(
    "key_id, expected",
    (
        pytest.param("foo", None, id="invalid format"),
        pytest.param("alias/foo", None, id="alias name"),
        pytest.param("880e7651-6f87-4c68-b84b-3220da5a7a02", None, id="key ID"),
        pytest.param("arn:aws:kms:moon-base-1:111222333444:alias/foo", "moon-base-1", id="alias ARN"),
        pytest.param(
            "arn:aws:kms:moon-base-1:111222333444:key/880e7651-6f87-4c68-b84b-3220da5a7a02", "moon-base-1", id="CMK ARN"
        ),
    ),
)
def test_region_from_key_id(key_id, expected):
    actual = _region_from_key_id(key_id=key_id)

    assert actual == expected
