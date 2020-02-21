# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Test suite for aws_encryption_sdk.materials_managers.default"""
import pytest
from mock import MagicMock, sentinel

import aws_encryption_sdk.materials_managers.default
from aws_encryption_sdk.exceptions import MasterKeyProviderError, SerializationError
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.defaults import ALGORITHM, ENCODED_SIGNER_KEY
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers import EncryptionMaterials
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo, RawDataKey

from ..unit_test_utils import (
    ephemeral_raw_aes_keyring,
    ephemeral_raw_aes_master_key,
    ephemeral_raw_rsa_keyring,
    ephemeral_raw_rsa_master_key,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_DATA_KEY = DataKey(
    key_provider=MasterKeyInfo(provider_id="Provider", key_info=b"Info"),
    data_key=b"1234567890123456789012",
    encrypted_data_key=b"asdf",
)
_ENCRYPTED_DATA_KEY = EncryptedDataKey.from_data_key(_DATA_KEY)


@pytest.fixture
def patch_for_dcmm_encrypt(mocker):
    mocker.patch.object(DefaultCryptoMaterialsManager, "_generate_signing_key_and_update_encryption_context")
    mock_signing_key = b"ex_signing_key"
    DefaultCryptoMaterialsManager._generate_signing_key_and_update_encryption_context.return_value = mock_signing_key
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "prepare_data_keys")
    mock_data_encryption_key = _DATA_KEY
    mock_encrypted_data_keys = (_ENCRYPTED_DATA_KEY,)
    result_pair = mock_data_encryption_key, mock_encrypted_data_keys
    aws_encryption_sdk.materials_managers.default.prepare_data_keys.return_value = result_pair
    yield result_pair, mock_signing_key


@pytest.fixture
def patch_for_dcmm_decrypt(mocker):
    mocker.patch.object(DefaultCryptoMaterialsManager, "_load_verification_key_from_encryption_context")
    mock_verification_key = b"ex_verification_key"
    DefaultCryptoMaterialsManager._load_verification_key_from_encryption_context.return_value = mock_verification_key
    yield mock_verification_key


def build_cmm():
    mock_mkp = MagicMock(__class__=MasterKeyProvider)
    mock_mkp.decrypt_data_key_from_list.return_value = _DATA_KEY
    mock_mkp.master_keys_for_encryption.return_value = (
        sentinel.primary_mk,
        {sentinel.primary_mk, sentinel.mk_a, sentinel.mk_b},
    )
    return DefaultCryptoMaterialsManager(master_key_provider=mock_mkp)


@pytest.mark.parametrize(
    "kwargs",
    (
        pytest.param(dict(), id="no parameters"),
        pytest.param(dict(master_key_provider=None, keyring=None), id="explicit None for both"),
        pytest.param(
            dict(master_key_provider=ephemeral_raw_aes_master_key(), keyring=ephemeral_raw_aes_keyring()),
            id="both provided",
        ),
    ),
)
def test_attributes_fail(kwargs):
    with pytest.raises(TypeError):
        DefaultCryptoMaterialsManager(**kwargs)


def test_attributes_default():
    cmm = DefaultCryptoMaterialsManager(master_key_provider=MagicMock(__class__=MasterKeyProvider))
    assert cmm.algorithm is ALGORITHM


def test_generate_signing_key_and_update_encryption_context_no_signer():
    cmm = build_cmm()

    test = cmm._generate_signing_key_and_update_encryption_context(
        algorithm=MagicMock(signing_algorithm_info=None), encryption_context={}
    )

    assert test is None


def test_generate_signing_key_and_update_encryption_context(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "Signer")
    mock_signer = MagicMock()
    aws_encryption_sdk.materials_managers.default.Signer.return_value = mock_signer
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "generate_ecc_signing_key")
    cmm = build_cmm()
    mock_algorithm = MagicMock(signing_algorithm_info=sentinel.eccurve)
    encryption_context = {"a": "b", "c": "d"}
    check_encryption_context = encryption_context.copy()
    check_encryption_context[ENCODED_SIGNER_KEY] = mock_signer.encoded_public_key.return_value

    test = cmm._generate_signing_key_and_update_encryption_context(
        algorithm=mock_algorithm, encryption_context=encryption_context
    )

    aws_encryption_sdk.materials_managers.default.generate_ecc_signing_key.assert_called_once_with(
        algorithm=mock_algorithm
    )
    aws_encryption_sdk.materials_managers.default.Signer.assert_called_once_with(
        algorithm=mock_algorithm,
        key=aws_encryption_sdk.materials_managers.default.generate_ecc_signing_key.return_value,
    )
    assert encryption_context[ENCODED_SIGNER_KEY] is mock_signer.encoded_public_key.return_value
    assert test is mock_signer.key_bytes.return_value
    # NOTE: This encryption context check is only fully assertable because we mock out the MKP
    assert check_encryption_context == encryption_context


def test_get_encryption_materials(patch_for_dcmm_encrypt):
    encryption_context = {"a": "b"}
    mock_request = MagicMock(algorithm=None, encryption_context=encryption_context)
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)

    cmm.master_key_provider.master_keys_for_encryption.assert_called_once_with(
        encryption_context=encryption_context,
        plaintext_rostream=mock_request.plaintext_rostream,
        plaintext_length=mock_request.plaintext_length,
    )
    cmm._generate_signing_key_and_update_encryption_context.assert_called_once_with(cmm.algorithm, encryption_context)
    aws_encryption_sdk.materials_managers.default.prepare_data_keys.assert_called_once_with(
        primary_master_key=cmm.master_key_provider.master_keys_for_encryption.return_value[0],
        master_keys=cmm.master_key_provider.master_keys_for_encryption.return_value[1],
        algorithm=cmm.algorithm,
        encryption_context=encryption_context,
    )
    assert isinstance(test, EncryptionMaterials)
    assert test.algorithm is cmm.algorithm
    assert test.data_encryption_key == RawDataKey.from_data_key(patch_for_dcmm_encrypt[0][0])
    assert test.encrypted_data_keys == patch_for_dcmm_encrypt[0][1]
    assert test.encryption_context == encryption_context
    assert test.signing_key == patch_for_dcmm_encrypt[1]


def test_get_encryption_materials_override_algorithm(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=MagicMock(__class__=Algorithm), encryption_context={})
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)

    assert test.algorithm is mock_request.algorithm


def test_get_encryption_materials_no_mks(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=MagicMock(__class__=Algorithm), encryption_context={})
    cmm = build_cmm()
    cmm.master_key_provider.master_keys_for_encryption.return_value = (None, set([]))

    with pytest.raises(MasterKeyProviderError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)

    excinfo.match(r"No Master Keys available from Master Key Provider")


def test_get_encryption_materials_primary_mk_not_in_mks(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=MagicMock(__class__=Algorithm), encryption_context={})
    cmm = build_cmm()
    cmm.master_key_provider.master_keys_for_encryption.return_value = (
        sentinel.primary_mk,
        {sentinel.mk_a, sentinel.mk_b},
    )

    with pytest.raises(MasterKeyProviderError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)

    excinfo.match(r"Primary Master Key not in provided Master Keys")


def test_load_verification_key_from_encryption_context_key_not_needed_and_not_found():
    cmm = build_cmm()

    test = cmm._load_verification_key_from_encryption_context(
        algorithm=MagicMock(signing_algorithm_info=None), encryption_context={}
    )

    assert test is None


def test_load_verification_key_from_encryption_context_key_is_needed_and_not_found():
    cmm = build_cmm()

    with pytest.raises(SerializationError) as excinfo:
        cmm._load_verification_key_from_encryption_context(
            algorithm=MagicMock(signing_algorithm_info=sentinel.not_none), encryption_context={}
        )

    excinfo.match(r"No signature verification key found in header for signed algorithm.")


def test_load_verification_key_from_encryption_context_key_found_but_not_needed():
    cmm = build_cmm()

    with pytest.raises(SerializationError) as excinfo:
        cmm._load_verification_key_from_encryption_context(
            algorithm=MagicMock(signing_algorithm_info=None),
            encryption_context={ENCODED_SIGNER_KEY: "something that exists"},
        )

    excinfo.match(r"Signature verification key found in header for non-signed algorithm.")


def test_load_verification_key_from_encryption_context_key_is_needed_and_is_found(mocker):
    mock_verifier = MagicMock()
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "Verifier")
    aws_encryption_sdk.materials_managers.default.Verifier.from_encoded_point.return_value = mock_verifier
    encryption_context = {ENCODED_SIGNER_KEY: sentinel.encoded_verification_key}
    mock_algorithm = MagicMock(signing_algorithm_info=sentinel.not_none)
    cmm = build_cmm()

    test = cmm._load_verification_key_from_encryption_context(
        algorithm=mock_algorithm, encryption_context=encryption_context
    )

    aws_encryption_sdk.materials_managers.default.Verifier.from_encoded_point.assert_called_once_with(
        algorithm=mock_algorithm, encoded_point=sentinel.encoded_verification_key
    )
    assert test is mock_verifier.key_bytes.return_value


def test_decrypt_materials(mocker, patch_for_dcmm_decrypt):
    mock_request = MagicMock()
    cmm = build_cmm()

    test = cmm.decrypt_materials(request=mock_request)

    cmm.master_key_provider.decrypt_data_key_from_list.assert_called_once_with(
        encrypted_data_keys=mock_request.encrypted_data_keys,
        algorithm=mock_request.algorithm,
        encryption_context=mock_request.encryption_context,
    )
    cmm._load_verification_key_from_encryption_context.assert_called_once_with(
        algorithm=mock_request.algorithm, encryption_context=mock_request.encryption_context
    )
    assert test.data_key == RawDataKey.from_data_key(cmm.master_key_provider.decrypt_data_key_from_list.return_value)
    assert test.verification_key == patch_for_dcmm_decrypt
