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
from mock import MagicMock, patch, sentinel

import aws_encryption_sdk.materials_managers.default
from aws_encryption_sdk.exceptions import MasterKeyProviderError, SerializationError
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.defaults import ALGORITHM, ENCODED_SIGNER_KEY
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers import (
    DecryptionMaterialsRequest,
    EncryptionMaterials,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo

from ..unit_test_utils import ephemeral_raw_rsa_master_key

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
    mock_data_encryption_key = _DATA_KEY
    mock_encrypted_data_keys = (_ENCRYPTED_DATA_KEY,)
    result_pair = mock_data_encryption_key, mock_encrypted_data_keys
    yield result_pair, mock_signing_key


@pytest.fixture
def patch_for_dcmm_decrypt(mocker):
    mocker.patch.object(DefaultCryptoMaterialsManager, "_load_verification_key_from_encryption_context")
    mock_verification_key = b"ex_verification_key"
    DefaultCryptoMaterialsManager._load_verification_key_from_encryption_context.return_value = mock_verification_key
    yield mock_verification_key


def build_cmm():
    return DefaultCryptoMaterialsManager(master_key_provider=ephemeral_raw_rsa_master_key())


@pytest.mark.parametrize(
    "mkp, keyring", ((None, None), (MagicMock(__class__=MasterKeyProvider), MagicMock(__class__=Keyring)))
)
def test_attributes_fail(mkp, keyring):
    with pytest.raises(TypeError):
        DefaultCryptoMaterialsManager(master_key_provider=mkp, keyring=keyring)


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
    request = EncryptionMaterialsRequest(encryption_context=encryption_context, frame_length=128)
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=request)

    assert isinstance(test, EncryptionMaterials)
    assert test.algorithm is cmm.algorithm
    assert test.data_encryption_key.data_key
    assert test.data_encryption_key.key_provider.provider_id == "fake"
    assert test.data_encryption_key.key_provider.key_id == b"rsa-4096"
    assert len(test.encrypted_data_keys) == 1
    assert test.encryption_context == encryption_context
    assert test.signing_key == patch_for_dcmm_encrypt[1]


def test_get_encryption_materials_override_algorithm(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=Algorithm.AES_128_GCM_IV12_TAG16, encryption_context={})
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)

    assert test.algorithm is mock_request.algorithm


def test_get_encryption_materials_no_mks(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=ALGORITHM, encryption_context={})
    cmm = build_cmm()

    with patch.object(cmm.master_key_provider, "master_keys_for_encryption", return_value=(None, set([]))):

        with pytest.raises(MasterKeyProviderError) as excinfo:
            cmm.get_encryption_materials(request=mock_request)

    excinfo.match(r"No Master Keys available from Master Key Provider")


def test_get_encryption_materials_primary_mk_not_in_mks(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=ALGORITHM, encryption_context={})
    cmm = build_cmm()
    with patch.object(
        cmm.master_key_provider,
        "master_keys_for_encryption",
        return_value=(sentinel.primary_mk, {sentinel.mk_a, sentinel.mk_b},),
    ):

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


def test_decrypt_materials(patch_for_dcmm_decrypt):
    cmm = build_cmm()
    dk = cmm.master_key_provider.generate_data_key(algorithm=ALGORITHM, encryption_context={})
    edk = EncryptedDataKey(key_provider=dk.key_provider, encrypted_data_key=dk.encrypted_data_key)

    test = cmm.decrypt_materials(
        request=DecryptionMaterialsRequest(algorithm=ALGORITHM, encryption_context={}, encrypted_data_keys={edk})
    )

    assert test.data_key.data_key == dk.data_key
    assert test.verification_key == patch_for_dcmm_decrypt
