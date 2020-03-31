# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for ``aws_encryption_sdk.keyrings.aws_kms``."""
import itertools
import logging
import os

import boto3
import pytest
from moto.kms import mock_kms

from aws_encryption_sdk.exceptions import DecryptKeyError, EncryptKeyError
from aws_encryption_sdk.identifiers import KeyringTraceFlag
from aws_encryption_sdk.internal.defaults import ALGORITHM
from aws_encryption_sdk.keyrings.aws_kms import (
    _PROVIDER_ID,
    KmsKeyring,
    _AwsKmsDiscoveryKeyring,
    _AwsKmsSingleCmkKeyring,
    _do_aws_kms_decrypt,
    _do_aws_kms_encrypt,
    _do_aws_kms_generate_data_key,
    _try_aws_kms_decrypt,
)
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import DefaultClientSupplier
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

# used as fixtures
from ...functional_test_utils import fake_generator  # noqa pylint: disable=unused-import
from ...functional_test_utils import fake_generator_and_child  # noqa pylint: disable=unused-import
from ...functional_test_utils import FAKE_REGION

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable, List  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.functional, pytest.mark.local]


def _matching_flags(wrapping_key, keyring_trace):
    # type: (MasterKeyInfo, Iterable[KeyringTrace]) -> List[KeyringTraceFlag]
    return list(
        itertools.chain.from_iterable([entry.flags for entry in keyring_trace if entry.wrapping_key == wrapping_key])
    )


def test_aws_kms_single_cmk_keyring_on_encrypt_empty_materials(fake_generator):
    keyring = _AwsKmsSingleCmkKeyring(key_id=fake_generator, client_supplier=DefaultClientSupplier())

    initial_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    result_materials = keyring.on_encrypt(initial_materials)

    assert result_materials.data_encryption_key is not None
    assert len(result_materials.encrypted_data_keys) == 1

    generator_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=fake_generator), result_materials.keyring_trace
    )

    assert KeyringTraceFlag.GENERATED_DATA_KEY in generator_flags
    assert KeyringTraceFlag.ENCRYPTED_DATA_KEY in generator_flags
    assert KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT in generator_flags


def test_aws_kms_single_cmk_keyring_on_encrypt_existing_data_key(fake_generator):
    keyring = _AwsKmsSingleCmkKeyring(key_id=fake_generator, client_supplier=DefaultClientSupplier())

    initial_materials = EncryptionMaterials(
        algorithm=ALGORITHM,
        encryption_context={},
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id="foo", key_info=b"bar"), data_key=os.urandom(ALGORITHM.kdf_input_len)
        ),
    )

    result_materials = keyring.on_encrypt(initial_materials)

    assert result_materials is not initial_materials
    assert result_materials.data_encryption_key is not None
    assert len(result_materials.encrypted_data_keys) == 1

    generator_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=fake_generator), result_materials.keyring_trace
    )

    assert KeyringTraceFlag.GENERATED_DATA_KEY not in generator_flags
    assert KeyringTraceFlag.ENCRYPTED_DATA_KEY in generator_flags
    assert KeyringTraceFlag.SIGNED_ENCRYPTION_CONTEXT in generator_flags


@mock_kms
def test_aws_kms_single_cmk_keyring_on_encrypt_fail():
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    keyring = _AwsKmsSingleCmkKeyring(key_id="foo", client_supplier=DefaultClientSupplier())

    initial_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    with pytest.raises(EncryptKeyError) as excinfo:
        keyring.on_encrypt(initial_materials)

    excinfo.match(r"Unable to generate or encrypt data key using *")


@mock_kms
def test_aws_kms_single_cmk_keyring_on_decrypt_existing_datakey(caplog):
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    caplog.set_level(logging.DEBUG)
    keyring = _AwsKmsSingleCmkKeyring(key_id="foo", client_supplier=DefaultClientSupplier())

    initial_materials = DecryptionMaterials(
        algorithm=ALGORITHM,
        encryption_context={},
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id="foo", key_info=b"bar"), data_key=os.urandom(ALGORITHM.kdf_input_len)
        ),
    )

    result_materials = keyring.on_decrypt(
        decryption_materials=initial_materials,
        encrypted_data_keys=(
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"foo"), encrypted_data_key=b"bar"
            ),
        ),
    )

    assert result_materials.data_encryption_key == initial_materials.data_encryption_key

    log_data = caplog.text
    # This means that it did NOT try to decrypt the EDK.
    assert "Unable to decrypt encrypted data key from" not in log_data


def test_aws_kms_single_cmk_keyring_on_decrypt_single_cmk(fake_generator):
    keyring = _AwsKmsSingleCmkKeyring(key_id=fake_generator, client_supplier=DefaultClientSupplier())

    initial_encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    encryption_materials = keyring.on_encrypt(initial_encryption_materials)

    initial_decryption_materials = DecryptionMaterials(
        algorithm=encryption_materials.algorithm, encryption_context=encryption_materials.encryption_context
    )

    result_materials = keyring.on_decrypt(
        decryption_materials=initial_decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    assert result_materials is not initial_decryption_materials
    assert result_materials.data_encryption_key is not None

    generator_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=fake_generator), result_materials.keyring_trace
    )

    assert KeyringTraceFlag.DECRYPTED_DATA_KEY in generator_flags
    assert KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT in generator_flags


def test_aws_kms_single_cmk_keyring_on_decrypt_multiple_cmk(fake_generator_and_child):
    generator, child = fake_generator_and_child

    encrypting_keyring = KmsKeyring(generator_key_id=generator, child_key_ids=(child,))
    decrypting_keyring = _AwsKmsSingleCmkKeyring(key_id=child, client_supplier=DefaultClientSupplier())

    initial_encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    encryption_materials = encrypting_keyring.on_encrypt(initial_encryption_materials)

    initial_decryption_materials = DecryptionMaterials(
        algorithm=encryption_materials.algorithm, encryption_context=encryption_materials.encryption_context
    )

    result_materials = decrypting_keyring.on_decrypt(
        decryption_materials=initial_decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    generator_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=generator), result_materials.keyring_trace
    )
    assert len(generator_flags) == 0

    child_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=child), result_materials.keyring_trace
    )

    assert KeyringTraceFlag.DECRYPTED_DATA_KEY in child_flags
    assert KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT in child_flags


def test_aws_kms_single_cmk_keyring_on_decrypt_no_match(fake_generator_and_child):
    generator, child = fake_generator_and_child

    encrypting_keyring = _AwsKmsSingleCmkKeyring(key_id=generator, client_supplier=DefaultClientSupplier())
    decrypting_keyring = _AwsKmsSingleCmkKeyring(key_id=child, client_supplier=DefaultClientSupplier())

    initial_encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    encryption_materials = encrypting_keyring.on_encrypt(initial_encryption_materials)

    initial_decryption_materials = DecryptionMaterials(
        algorithm=encryption_materials.algorithm, encryption_context=encryption_materials.encryption_context
    )

    result_materials = decrypting_keyring.on_decrypt(
        decryption_materials=initial_decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    assert result_materials.data_encryption_key is None


@mock_kms
def test_aws_kms_single_cmk_keyring_on_decrypt_fail(caplog):
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    caplog.set_level(logging.DEBUG)
    keyring = _AwsKmsSingleCmkKeyring(key_id="foo", client_supplier=DefaultClientSupplier())

    initial_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    result_materials = keyring.on_decrypt(
        decryption_materials=initial_materials,
        encrypted_data_keys=(
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"foo"), encrypted_data_key=b"bar"
            ),
        ),
    )

    assert not result_materials.data_encryption_key

    log_data = caplog.text

    # This means that it did actually try to decrypt the EDK but encountered an error talking to KMS.
    assert "Unable to decrypt encrypted data key from" in log_data


def test_aws_kms_discovery_keyring_on_encrypt():
    keyring = _AwsKmsDiscoveryKeyring(client_supplier=DefaultClientSupplier())

    initial_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    result_materials = keyring.on_encrypt(initial_materials)

    assert result_materials is initial_materials
    assert len(result_materials.encrypted_data_keys) == 0


@pytest.fixture
def encryption_materials_for_discovery_decrypt(fake_generator):
    encrypting_keyring = _AwsKmsSingleCmkKeyring(key_id=fake_generator, client_supplier=DefaultClientSupplier())

    initial_encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    return fake_generator, encrypting_keyring.on_encrypt(initial_encryption_materials)


def test_aws_kms_discovery_keyring_on_decrypt(encryption_materials_for_discovery_decrypt):
    generator_key_id, encryption_materials = encryption_materials_for_discovery_decrypt

    decrypting_keyring = _AwsKmsDiscoveryKeyring(client_supplier=DefaultClientSupplier())

    initial_decryption_materials = DecryptionMaterials(
        algorithm=encryption_materials.algorithm, encryption_context=encryption_materials.encryption_context
    )

    result_materials = decrypting_keyring.on_decrypt(
        decryption_materials=initial_decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    assert result_materials is not initial_decryption_materials
    assert result_materials.data_encryption_key is not None

    generator_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=generator_key_id), result_materials.keyring_trace
    )

    assert KeyringTraceFlag.DECRYPTED_DATA_KEY in generator_flags
    assert KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT in generator_flags


@mock_kms
def test_aws_kms_discovery_keyring_on_decrypt_existing_data_key(caplog):
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    caplog.set_level(logging.DEBUG)
    keyring = _AwsKmsDiscoveryKeyring(client_supplier=DefaultClientSupplier())

    initial_materials = DecryptionMaterials(
        algorithm=ALGORITHM,
        encryption_context={},
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id="foo", key_info=b"bar"), data_key=os.urandom(ALGORITHM.kdf_input_len)
        ),
    )

    result_materials = keyring.on_decrypt(
        decryption_materials=initial_materials,
        encrypted_data_keys=(
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"foo"), encrypted_data_key=b"bar"
            ),
        ),
    )

    assert result_materials.data_encryption_key == initial_materials.data_encryption_key

    log_data = caplog.text
    # This means that it did NOT try to decrypt the EDK.
    assert "Unable to decrypt encrypted data key from" not in log_data


@mock_kms
def test_aws_kms_discovery_keyring_on_decrypt_no_matching_edk(caplog):
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    caplog.set_level(logging.DEBUG)
    keyring = _AwsKmsDiscoveryKeyring(client_supplier=DefaultClientSupplier())

    initial_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context={},)

    result_materials = keyring.on_decrypt(
        decryption_materials=initial_materials,
        encrypted_data_keys=(
            EncryptedDataKey(key_provider=MasterKeyInfo(provider_id="foo", key_info=b"bar"), encrypted_data_key=b"bar"),
        ),
    )

    assert result_materials.data_encryption_key is None

    log_data = caplog.text
    # This means that it did NOT try to decrypt the EDK.
    assert "Unable to decrypt encrypted data key from" not in log_data


@mock_kms
def test_aws_kms_discovery_keyring_on_decrypt_fail(caplog):
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    caplog.set_level(logging.DEBUG)
    keyring = _AwsKmsDiscoveryKeyring(client_supplier=DefaultClientSupplier())

    initial_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context={},)

    result_materials = keyring.on_decrypt(
        decryption_materials=initial_materials,
        encrypted_data_keys=(
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"bar"), encrypted_data_key=b"bar"
            ),
        ),
    )

    assert result_materials.data_encryption_key is None

    log_data = caplog.text
    # This means that it did actually try to decrypt the EDK but encountered an error talking to KMS.
    assert "Unable to decrypt encrypted data key from" in log_data


def test_try_aws_kms_decrypt_succeed(fake_generator):
    encryption_context = {"foo": "bar"}
    kms = boto3.client("kms", region_name=FAKE_REGION)
    plaintext = b"0123" * 8
    response = kms.encrypt(KeyId=fake_generator, Plaintext=plaintext, EncryptionContext=encryption_context)

    encrypted_data_key = EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=response["KeyId"]),
        encrypted_data_key=response["CiphertextBlob"],
    )

    initial_decryption_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context=encryption_context,)

    result_materials = _try_aws_kms_decrypt(
        client_supplier=DefaultClientSupplier(),
        decryption_materials=initial_decryption_materials,
        grant_tokens=[],
        encrypted_data_key=encrypted_data_key,
    )

    assert result_materials.data_encryption_key.data_key == plaintext

    generator_flags = _matching_flags(
        MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=fake_generator), result_materials.keyring_trace
    )

    assert KeyringTraceFlag.DECRYPTED_DATA_KEY in generator_flags
    assert KeyringTraceFlag.VERIFIED_ENCRYPTION_CONTEXT in generator_flags


@mock_kms
def test_try_aws_kms_decrypt_error(caplog):
    # In this context there are no KMS CMKs, so any calls to KMS will fail.
    caplog.set_level(logging.DEBUG)

    encrypted_data_key = EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"foo"), encrypted_data_key=b"bar"
    )

    initial_decryption_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context={},)

    result_materials = _try_aws_kms_decrypt(
        client_supplier=DefaultClientSupplier(),
        decryption_materials=initial_decryption_materials,
        grant_tokens=[],
        encrypted_data_key=encrypted_data_key,
    )

    assert result_materials.data_encryption_key is None

    log_data = caplog.text
    # This means that it did actually try to decrypt the EDK but encountered an error talking to KMS.
    assert "Unable to decrypt encrypted data key from" in log_data


def test_do_aws_kms_decrypt(fake_generator):
    encryption_context = {"foo": "bar"}
    kms = boto3.client("kms", region_name=FAKE_REGION)
    plaintext = b"0123" * 8
    response = kms.encrypt(KeyId=fake_generator, Plaintext=plaintext, EncryptionContext=encryption_context)

    encrypted_data_key = EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=response["KeyId"]),
        encrypted_data_key=response["CiphertextBlob"],
    )

    decrypted_data_key = _do_aws_kms_decrypt(
        client_supplier=DefaultClientSupplier(),
        key_name=fake_generator,
        encrypted_data_key=encrypted_data_key,
        encryption_context=encryption_context,
        grant_tokens=[],
    )
    assert decrypted_data_key.data_key == plaintext


def test_do_aws_kms_decrypt_unexpected_key_id(fake_generator_and_child):
    encryptor, decryptor = fake_generator_and_child
    encryption_context = {"foo": "bar"}
    kms = boto3.client("kms", region_name=FAKE_REGION)
    plaintext = b"0123" * 8
    response = kms.encrypt(KeyId=encryptor, Plaintext=plaintext, EncryptionContext=encryption_context)

    encrypted_data_key = EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=response["KeyId"]),
        encrypted_data_key=response["CiphertextBlob"],
    )

    with pytest.raises(DecryptKeyError) as excinfo:
        _do_aws_kms_decrypt(
            client_supplier=DefaultClientSupplier(),
            key_name=decryptor,
            encrypted_data_key=encrypted_data_key,
            encryption_context=encryption_context,
            grant_tokens=[],
        )

    excinfo.match(r"Decryption results from AWS KMS are for an unexpected key ID*")


def test_do_aws_kms_encrypt(fake_generator):
    encryption_context = {"foo": "bar"}
    plaintext = b"0123" * 8

    encrypted_key = _do_aws_kms_encrypt(
        client_supplier=DefaultClientSupplier(),
        key_name=fake_generator,
        plaintext_data_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=fake_generator), data_key=plaintext
        ),
        encryption_context=encryption_context,
        grant_tokens=[],
    )

    kms = boto3.client("kms", region_name=FAKE_REGION)
    response = kms.decrypt(CiphertextBlob=encrypted_key.encrypted_data_key, EncryptionContext=encryption_context)

    assert response["Plaintext"] == plaintext


def test_do_aws_kms_generate_data_key(fake_generator):
    encryption_context = {"foo": "bar"}
    plaintext_key, encrypted_key = _do_aws_kms_generate_data_key(
        client_supplier=DefaultClientSupplier(),
        key_name=fake_generator,
        encryption_context=encryption_context,
        algorithm=ALGORITHM,
        grant_tokens=[],
    )

    kms = boto3.client("kms", region_name=FAKE_REGION)
    response = kms.decrypt(CiphertextBlob=encrypted_key.encrypted_data_key, EncryptionContext=encryption_context)

    assert response["Plaintext"] == plaintext_key.data_key
