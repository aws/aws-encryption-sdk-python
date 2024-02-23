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
"""Unit test suite to validate aws_encryption_sdk.materials_managers.mpl.cmm logic."""

import pytest
from mock import MagicMock, patch


from aws_encryption_sdk.identifiers import CommitmentPolicy
import aws_encryption_sdk.materials_managers.mpl.cmm
from aws_encryption_sdk.materials_managers.mpl.cmm import MPLCMMHandler
from aws_encryption_sdk.materials_managers.mpl.materials import (
    MPLEncryptionMaterials,
    MPLDecryptionMaterials,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


from aws_cryptographic_materialproviders.mpl.errors import AwsCryptographicMaterialProvidersException
from aws_cryptographic_materialproviders.mpl.models import (
    AlgorithmSuiteIdESDK,
    CommitmentPolicyESDK,
    DecryptMaterialsInput,
    DecryptionMaterials as MPL_DecryptionMaterials,
    EncryptionMaterials as MPL_EncryptionMaterials,
    GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
)
from aws_cryptographic_materialproviders.mpl.references import (
    ICryptographicMaterialsManager
)

mock_mpl_cmm = MagicMock(__class__=ICryptographicMaterialsManager)
mock_mpl_encryption_materials = MagicMock(__class__=MPL_EncryptionMaterials)
mock_mpl_decrypt_materials = MagicMock(__class__=MPL_DecryptionMaterials)


from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.materials_managers import (
    EncryptionMaterialsRequest,
    DecryptionMaterialsRequest,
)


mock_encryption_materials_request = MagicMock(__class__=EncryptionMaterialsRequest)
mock_encryption_materials_handler = MagicMock(__class__=MPLEncryptionMaterials)
mock_decryption_materials_request = MagicMock(__class__=DecryptionMaterialsRequest)


def test_GIVEN_test_has_mpl_is_False_WHEN_create_MPLCMMHandler_with_valid_mpl_cmm_THEN_return_new_MPLCMMHandler():
    mpl_cmm_handler = MPLCMMHandler(mpl_cmm=mock_mpl_cmm)
    
    assert mpl_cmm_handler.mpl_cmm == mock_mpl_cmm


def test_GIVEN_test_has_mpl_is_False_WHEN_create_MPLCMMHandler_with_invalid_mpl_cmm_THEN_raise_ValueError():
    with pytest.raises(ValueError):
        MPLCMMHandler(mpl_cmm="not a valid mpl_cmm")


@patch.object(mock_mpl_cmm, "get_encryption_materials")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._native_to_mpl_get_encryption_materials")
def test_GIVEN_valid_request_WHEN_call_get_encryption_materials_THEN_return_MPLEncryptionMaterials(
    mock_native_to_mpl_get_encryption_materials,
    mock_get_encryption_materials,
):
    
    # Mock: mpl_cmm.get_encryption_materials returns mock MPL encryption materials
    mock_get_encryption_materials_output = MagicMock(__class__=GetEncryptionMaterialsOutput)
    mock_get_encryption_materials_output.encryption_materials = mock_mpl_encryption_materials
    mock_get_encryption_materials.return_value = mock_get_encryption_materials_output

    # Mock: CMMHandler._native_to_mpl_get_encryption_materials creates a GetEncryptionMaterialsInput
    mock_get_encryption_materials_input = MagicMock(__class__=GetEncryptionMaterialsInput)
    mock_native_to_mpl_get_encryption_materials.return_value = mock_get_encryption_materials_input

    cmm_handler = MPLCMMHandler(mpl_cmm=mock_mpl_cmm)
    test = cmm_handler.get_encryption_materials(mock_encryption_materials_request)

    # Verify cmm_handler returns MPLEncryptionMaterials
    assert isinstance(test, MPLEncryptionMaterials)
    # Verify returned EncryptionMaterialsHandler uses the output of `get_encryption_materials`
    assert test.mpl_materials == mock_mpl_encryption_materials
    # Verify we actually called `get_encryption_materials`
    mock_mpl_cmm.get_encryption_materials.assert_called_once_with(mock_get_encryption_materials_input)


@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._native_to_mpl_commmitment_policy")
def test_GIVEN_get_encryption_materials_raises_MPL_Exception_WHEN_call_get_encryption_materials_THEN_raise_ESDK_Exception(
    _
):
    with pytest.raises(AWSEncryptionSDKClientError):
        with patch.object(mock_mpl_cmm, "get_encryption_materials",
                        side_effect=AwsCryptographicMaterialProvidersException("any")):
            
            cmm_handler = MPLCMMHandler(mpl_cmm=mock_mpl_cmm)
            cmm_handler.get_encryption_materials(mock_encryption_materials_request)

@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._native_to_mpl_commmitment_policy")
def test_GIVEN_native_to_mpl_commmitment_policy_returns_valid_policy_WHEN_call_native_to_mpl_get_encryption_materials_THEN_returns_GetEncryptionMaterialsInput(
    mock_mpl_commitment_policy
):
    mock_commitment_policy = MagicMock(__class__=CommitmentPolicyESDK)
    mock_mpl_commitment_policy.return_value = mock_commitment_policy

    output = MPLCMMHandler._native_to_mpl_get_encryption_materials(mock_encryption_materials_request)

    # verify correctness of returned value
    assert isinstance(output, GetEncryptionMaterialsInput)
    assert output.encryption_context == mock_encryption_materials_request.encryption_context
    assert output.commitment_policy == mock_commitment_policy
    assert output.max_plaintext_length == mock_encryption_materials_request.plaintext_length


def test_GIVEN_CommitmentPolicy_FORBID_ENCRYPT_ALLOW_DECRYPT_WHEN_call_native_to_mpl_commmitment_policyTHEN_returns_CommitmentPolicyESDK_FORBID_ENCRYPT_ALLOW_DECRYPT():
    native_commitment_policy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT

    output = MPLCMMHandler._native_to_mpl_commmitment_policy(native_commitment_policy)

    assert isinstance(output, CommitmentPolicyESDK)
    assert output.value == "FORBID_ENCRYPT_ALLOW_DECRYPT"

def test_GIVEN_CommitmentPolicy_REQUIRE_ENCRYPT_ALLOW_DECRYPT_WHEN_call_native_to_mpl_commmitment_policyTHEN_returns_CommitmentPolicyESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT():
    native_commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT

    output = MPLCMMHandler._native_to_mpl_commmitment_policy(native_commitment_policy)

    assert isinstance(output, CommitmentPolicyESDK)
    assert output.value == "REQUIRE_ENCRYPT_ALLOW_DECRYPT"

def test_GIVEN_CommitmentPolicy_REQUIRE_ENCRYPT_REQUIRE_DECRYPT_WHEN_call_native_to_mpl_commmitment_policyTHEN_returns_CommitmentPolicyESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT():
    native_commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT

    output = MPLCMMHandler._native_to_mpl_commmitment_policy(native_commitment_policy)

    assert isinstance(output, CommitmentPolicyESDK)
    assert output.value == "REQUIRE_ENCRYPT_REQUIRE_DECRYPT"

def test_GIVEN_CommitmentPolicy_unrecognized_WHEN_call_native_to_mpl_commmitment_policyTHEN_raise_ValueError():
    native_commitment_policy = "not a commitment policy"

    with pytest.raises(ValueError):
        MPLCMMHandler._native_to_mpl_commmitment_policy(native_commitment_policy)

@patch.object(mock_mpl_cmm, "decrypt_materials")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._create_mpl_decrypt_materials_input_from_request")
def test_GIVEN_valid_request_WHEN_call_decrypt_materials_THEN_return_MPLDecryptionMaterials(
    mock_native_to_mpl_decrypt_materials,
    mock_get_encryption_materials,
):
    
    # Mock: mpl_cmm.get_decryption_materials returns mock MPL decryption materials
    mock_decrypt_materials_output = MagicMock(__class__=GetEncryptionMaterialsOutput)
    mock_decrypt_materials_output.decryption_materials = mock_mpl_decrypt_materials
    mock_get_encryption_materials.return_value = mock_decrypt_materials_output

    # Mock: CMMHandler._create_mpl_decrypt_materials_input_from_request creates a DecryptMaterialsInput
    mock_decrypt_materials_input = MagicMock(__class__=GetEncryptionMaterialsInput)
    mock_native_to_mpl_decrypt_materials.return_value = mock_decrypt_materials_input

    cmm_handler = MPLCMMHandler(mpl_cmm=mock_mpl_cmm)
    output = cmm_handler.decrypt_materials(mock_decryption_materials_request)

    # Verify cmm_handler returns MPLDecryptionMaterials
    assert isinstance(output, MPLDecryptionMaterials)
    # Verify returned MPLDecryptionMaterials uses the output of `decrypt_materials`
    assert output.mpl_materials == mock_mpl_decrypt_materials
    # Verify we actually called `decrypt_materials`
    mock_mpl_cmm.decrypt_materials.assert_called_once_with(mock_decrypt_materials_input)

@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._create_mpl_decrypt_materials_input_from_request")
def test_GIVEN_decrypt_materials_raises_MPL_Exception_WHEN_call_decrypt_materials_THEN_raise_ESDK_Exception(
    _
):
    with pytest.raises(AWSEncryptionSDKClientError):
        with patch.object(mock_mpl_cmm, "decrypt_materials",
                        side_effect=AwsCryptographicMaterialProvidersException("any")):
            
            cmm_handler = MPLCMMHandler(mpl_cmm=mock_mpl_cmm)
            cmm_handler.decrypt_materials(mock_decryption_materials_request)

def test_WHEN_call_native_algorithm_id_to_mpl_algorithm_id_THEN_returns_valid_AlgorithmSuiteIdESDK():
    some_native_algorithm_id = 0x0000  # Not a real algorithm ID, but fits the format

    mpl_output = MPLCMMHandler._native_algorithm_id_to_mpl_algorithm_id(
        some_native_algorithm_id
    )

    assert isinstance(mpl_output, AlgorithmSuiteIdESDK)
    assert mpl_output.value == "0x0000"

@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._native_algorithm_id_to_mpl_algorithm_id")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.MPLCMMHandler._native_to_mpl_commmitment_policy")
def test__create_mpl_decrypt_materials_input_from_request(
    mock_mpl_commitment_policy,
    mock_mpl_algorithm_id,
):
    mock_algorithm_id = "0x1234"  # Some fake algorithm ID that fits the format
    mock_mpl_algorithm_id.return_value = mock_algorithm_id
    mock_commitment_policy = MagicMock(__class__=CommitmentPolicyESDK)
    mock_mpl_commitment_policy.return_value = mock_commitment_policy

    # mock_decryption_materials_request.algorithm = 

    output = MPLCMMHandler._create_mpl_decrypt_materials_input_from_request(mock_decryption_materials_request)

    assert isinstance(output, DecryptMaterialsInput)
    assert output.algorithm_suite_id == mock_algorithm_id
    assert output.commitment_policy == mock_commitment_policy
    assert output.encryption_context == mock_decryption_materials_request.encryption_context

    assert len(output.encrypted_data_keys) == len(mock_decryption_materials_request.encrypted_data_keys)
    for i in range(len(output.encrypted_data_keys)):
        # Assume input[i] == output[i], seems to work
        output_edk = output.encrypted_data_keys[i]
        input_edk = mock_decryption_materials_request[i]
        assert output_edk.key_provider_id == input_edk.key_provider.provider_id
        assert output_edk.key_provider_info == input_edk.key_provider.key_info
        assert output_edk.ciphertext == input_edk.encrypted_data_key
