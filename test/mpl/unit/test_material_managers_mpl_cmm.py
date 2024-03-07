# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.materials_managers.mpl.cmm logic.

The aws-cryptographic-materials-library MUST be installed to run tests in this module.
"""

import pytest
from aws_cryptographic_materialproviders.mpl.errors import AwsCryptographicMaterialProvidersException
from aws_cryptographic_materialproviders.mpl.models import (
    AlgorithmSuiteIdESDK as MPL_AlgorithmSuiteIdESDK,
    CommitmentPolicyESDK as MPL_CommitmentPolicyESDK,
    DecryptionMaterials as MPL_DecryptionMaterials,
    DecryptMaterialsInput as MPL_DecryptMaterialsInput,
    EncryptionMaterials as MPL_EncryptionMaterials,
    GetEncryptionMaterialsInput as MPL_GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput as MPL_GetEncryptionMaterialsOutput,
)
from aws_cryptographic_materialproviders.mpl.references import (
    ICryptographicMaterialsManager as MPL_ICryptographicMaterialsManager,
)
from mock import MagicMock, patch

from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.identifiers import CommitmentPolicy
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest
from aws_encryption_sdk.materials_managers.mpl.cmm import CryptoMaterialsManagerFromMPL
from aws_encryption_sdk.materials_managers.mpl.materials import DecryptionMaterialsFromMPL, EncryptionMaterialsFromMPL
from aws_encryption_sdk.structures import EncryptedDataKey as Native_EncryptedDataKey

pytestmark = [pytest.mark.unit, pytest.mark.local]


mock_encryption_materials_request = MagicMock(__class__=EncryptionMaterialsRequest)
mock_decryption_materials_request = MagicMock(__class__=DecryptionMaterialsRequest)


mock_mpl_cmm = MagicMock(__class__=MPL_ICryptographicMaterialsManager)
mock_mpl_encryption_materials = MagicMock(__class__=MPL_EncryptionMaterials)
mock_mpl_decrypt_materials = MagicMock(__class__=MPL_DecryptionMaterials)


mock_edk = MagicMock(__class__=Native_EncryptedDataKey)
mock_mpl_key_provider_id = MagicMock(__class__=str)
mock_edk.key_provider.provider_id = mock_mpl_key_provider_id
mock_mpl_key_provider_info = MagicMock(__class__=bytes)
mock_edk.key_provider.key_info = mock_mpl_key_provider_info
mock_mpl_encrypted_data_key = MagicMock(__class__=bytes)
mock_edk.encrypted_data_key = mock_mpl_encrypted_data_key


def test_GIVEN_valid_mpl_cmm_WHEN_create_CryptoMaterialsManagerFromMPL_THEN_return_new_CryptoMaterialsManagerFromMPL():
    # Given: valid mpl_cmm
    # When: create new CryptoMaterialsManagerFromMPL
    mpl_cmm = CryptoMaterialsManagerFromMPL(mpl_cmm=mock_mpl_cmm)
    # Then: CryptoMaterialsManagerFromMPL is valid
    assert mpl_cmm.mpl_cmm == mock_mpl_cmm


def test_GIVEN_invalid_mpl_cmm_WHEN_create_CryptoMaterialsManagerFromMPL_THEN_raise_ValueError():
    # Then: raises ValueError
    with pytest.raises(ValueError):
        # Given: invalid mpl_cmm
        # When: create new CryptoMaterialsManagerFromMPL
        CryptoMaterialsManagerFromMPL(mpl_cmm="not a valid mpl_cmm")


@patch.object(mock_mpl_cmm, "get_encryption_materials")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._native_to_mpl_get_encryption_materials")
def test_GIVEN_valid_request_WHEN_get_encryption_materials_THEN_return_EncryptionMaterialsFromMPL(
    mock_native_to_mpl_get_encryption_materials,
    mock_get_encryption_materials,
):

    # Given: _native_to_mpl_get_encryption_materials creates a MPL_GetEncryptionMaterialsInput
    mock_get_encryption_materials_input = MagicMock(__class__=MPL_GetEncryptionMaterialsInput)
    mock_native_to_mpl_get_encryption_materials.return_value = mock_get_encryption_materials_input

    # Given: mpl_cmm.get_encryption_materials returns mock MPL encryption materials
    mock_get_encryption_materials_output = MagicMock(__class__=MPL_GetEncryptionMaterialsOutput)
    mock_get_encryption_materials_output.encryption_materials = mock_mpl_encryption_materials
    mock_get_encryption_materials.return_value = mock_get_encryption_materials_output

    # When: get_encryption_materials
    cmm = CryptoMaterialsManagerFromMPL(mpl_cmm=mock_mpl_cmm)
    output = cmm.get_encryption_materials(mock_encryption_materials_request)

    # Then:
    # Verify cmm returns EncryptionMaterialsFromMPL
    assert isinstance(output, EncryptionMaterialsFromMPL)
    # Verify returned EncryptionMaterialsHandler uses the output of `get_encryption_materials`
    assert output.mpl_materials == mock_mpl_encryption_materials
    # Verify we actually called `get_encryption_materials`
    mock_mpl_cmm.get_encryption_materials.assert_called_once_with(mock_get_encryption_materials_input)


@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._native_to_mpl_get_encryption_materials")
def test_GIVEN_mpl_cmm_raises_MPLException_WHEN_get_encryption_materials_THEN_raise_ESDKException(
    _
):
    # Then: Raises AWSEncryptionSDKClientError
    with pytest.raises(AWSEncryptionSDKClientError):
        # Given: mpl_cmm.get_encryption_materials raises MPL exception
        with patch.object(mock_mpl_cmm, "get_encryption_materials",
                          side_effect=AwsCryptographicMaterialProvidersException("any")):
            # When: get_encryption_materials
            cmm = CryptoMaterialsManagerFromMPL(mpl_cmm=mock_mpl_cmm)
            cmm.get_encryption_materials(mock_encryption_materials_request)


@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._native_algorithm_id_to_mpl_algorithm_id")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._native_to_mpl_commmitment_policy")
def test_GIVEN_valid_mpl_commitment_policy_WHEN_native_to_mpl_get_encryption_materials_THEN_returns_MPL_GetEncryptionMaterialsInput(  # noqa: E501
    mock_mpl_commitment_policy,
    mock_mpl_algorithm,
):
    # Given: commitment policy is some MPL ESDK commitment policy
    mock_commitment_policy = MagicMock(__class__=MPL_CommitmentPolicyESDK)
    mock_mpl_commitment_policy.return_value = mock_commitment_policy

    # When: _native_to_mpl_get_encryption_materials
    output = CryptoMaterialsManagerFromMPL._native_to_mpl_get_encryption_materials(
        mock_encryption_materials_request
    )

    # Then: returned MPL_GetEncryptionMaterialsInput is correct
    assert isinstance(output, MPL_GetEncryptionMaterialsInput)
    assert output.encryption_context == mock_encryption_materials_request.encryption_context
    assert output.commitment_policy == mock_commitment_policy
    assert output.max_plaintext_length == mock_encryption_materials_request.plaintext_length
    assert output.algorithm_suite_id == mock_mpl_algorithm()


def test_GIVEN_CommitmentPolicy_FORBID_ENCRYPT_ALLOW_DECRYPT_WHEN_native_to_mpl_commmitment_policy_THEN_returns_MPL_CommitmentPolicyESDK_FORBID_ENCRYPT_ALLOW_DECRYPT():  # noqa: E501
    # Given: native FORBID_ENCRYPT_ALLOW_DECRYPT
    native_commitment_policy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT

    # When: _native_to_mpl_commmitment_policy
    output = CryptoMaterialsManagerFromMPL._native_to_mpl_commmitment_policy(native_commitment_policy)

    # Then: Returns MPL FORBID_ENCRYPT_ALLOW_DECRYPT
    assert isinstance(output, MPL_CommitmentPolicyESDK)
    assert output.value == "FORBID_ENCRYPT_ALLOW_DECRYPT"


def test_GIVEN_CommitmentPolicy_REQUIRE_ENCRYPT_ALLOW_DECRYPT_WHEN_native_to_mpl_commmitment_policy_THEN_returns_MPL_CommitmentPolicyESDK_REQUIRE_ENCRYPT_ALLOW_DECRYPT():  # noqa: E501
    # Given: native REQUIRE_ENCRYPT_ALLOW_DECRYPT
    native_commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT

    # When: _native_to_mpl_commmitment_policy
    output = CryptoMaterialsManagerFromMPL._native_to_mpl_commmitment_policy(native_commitment_policy)

    # Then: Returns MPL REQUIRE_ENCRYPT_ALLOW_DECRYPT
    assert isinstance(output, MPL_CommitmentPolicyESDK)
    assert output.value == "REQUIRE_ENCRYPT_ALLOW_DECRYPT"


def test_GIVEN_CommitmentPolicy_REQUIRE_ENCRYPT_REQUIRE_DECRYPT_WHEN_native_to_mpl_commmitment_policy_THEN_returns_MPL_CommitmentPolicyESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT():  # noqa: E501
    # Given: native REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    native_commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT

    # When: _native_to_mpl_commmitment_policy
    output = CryptoMaterialsManagerFromMPL._native_to_mpl_commmitment_policy(native_commitment_policy)

    # Then: Returns MPL REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    assert isinstance(output, MPL_CommitmentPolicyESDK)
    assert output.value == "REQUIRE_ENCRYPT_REQUIRE_DECRYPT"


def test_GIVEN_CommitmentPolicy_unrecognized_WHEN_native_to_mpl_commmitment_policy_THEN_raise_ValueError():
    # Given: invalid native commitment policy
    native_commitment_policy = "not a commitment policy"

    # Then: Raises ValueError
    with pytest.raises(ValueError):
        # When: _native_to_mpl_commmitment_policy
        CryptoMaterialsManagerFromMPL._native_to_mpl_commmitment_policy(native_commitment_policy)


@patch.object(mock_mpl_cmm, "decrypt_materials")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._create_mpl_decrypt_materials_input_from_request")
def test_GIVEN_valid_request_WHEN_decrypt_materials_THEN_return_DecryptionMaterialsFromMPL(
    mock_native_to_mpl_decrypt_materials,
    mock_get_encryption_materials,
):
    # Given: mpl_cmm.get_decryption_materials returns mock MPL decryption materials
    mock_decrypt_materials_output = MagicMock(__class__=MPL_GetEncryptionMaterialsOutput)
    mock_decrypt_materials_output.decryption_materials = mock_mpl_decrypt_materials
    mock_get_encryption_materials.return_value = mock_decrypt_materials_output

    # Given: CMMHandler._create_mpl_decrypt_materials_input_from_request creates a MPL_DecryptMaterialsInput
    mock_decrypt_materials_input = MagicMock(__class__=MPL_GetEncryptionMaterialsInput)
    mock_native_to_mpl_decrypt_materials.return_value = mock_decrypt_materials_input

    # When: decrypt_materials
    cmm = CryptoMaterialsManagerFromMPL(mpl_cmm=mock_mpl_cmm)
    output = cmm.decrypt_materials(mock_decryption_materials_request)

    # Then:
    # Verify cmm returns DecryptionMaterialsFromMPL
    assert isinstance(output, DecryptionMaterialsFromMPL)
    # Verify returned DecryptionMaterialsFromMPL uses the output of `decrypt_materials`
    assert output.mpl_materials == mock_mpl_decrypt_materials
    # Verify we actually called `decrypt_materials`
    mock_mpl_cmm.decrypt_materials.assert_called_once_with(mock_decrypt_materials_input)


@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._create_mpl_decrypt_materials_input_from_request")
def test_GIVEN_decrypt_materials_raises_MPL_Exception_WHEN_call_decrypt_materials_THEN_raise_ESDK_Exception(
    _
):
    # Then: Raises AWSEncryptionSDKClientError
    with pytest.raises(AWSEncryptionSDKClientError):
        # Given: mpl_cmm.decrypt_materials raises MPL exception
        with patch.object(mock_mpl_cmm, "decrypt_materials",
                          side_effect=AwsCryptographicMaterialProvidersException("any")):
            # When: decrypt_materials
            cmm = CryptoMaterialsManagerFromMPL(mpl_cmm=mock_mpl_cmm)
            cmm.decrypt_materials(mock_decryption_materials_request)


def test_GIVEN_valid_native_algorithm_id_WHEN_native_algorithm_id_to_mpl_algorithm_id_THEN_returns_valid_MPL_AlgorithmSuiteIdESDK():  # noqa: E501
    # Given: any native algorithm ID
    some_native_algorithm_id = 0x1234  # Not a real algorithm ID, but fits the format

    # When: _native_algorithm_id_to_mpl_algorithm_id
    mpl_output = CryptoMaterialsManagerFromMPL._native_algorithm_id_to_mpl_algorithm_id(
        some_native_algorithm_id
    )

    # Then: returns valid MPL algorithm ID
    assert isinstance(mpl_output, MPL_AlgorithmSuiteIdESDK)
    assert mpl_output.value == "0x1234"


@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._native_algorithm_id_to_mpl_algorithm_id")
@patch("aws_encryption_sdk.materials_managers.mpl.cmm.CryptoMaterialsManagerFromMPL"
       "._native_to_mpl_commmitment_policy")
def test_GIVEN_valid_request_WHEN_create_mpl_decrypt_materials_input_from_request_THEN_returns_MPL_MPL_DecryptMaterialsInput(  # noqa: E501
    mock_mpl_commitment_policy,
    mock_mpl_algorithm_id,
):
    # Given: _native_algorithm_id_to_mpl_algorithm_id returns a valid MPL algorithm ID
    mock_algorithm_id = "0x1234"  # Some fake algorithm ID that fits the format
    mock_mpl_algorithm_id.return_value = mock_algorithm_id

    # Given: _native_to_mpl_commmitment_policy returns some MPL commitment policy
    mock_commitment_policy = MagicMock(__class__=MPL_CommitmentPolicyESDK)
    mock_mpl_commitment_policy.return_value = mock_commitment_policy

    no_mock_edks = [mock_edk]
    one_mock_edk = [mock_edk]
    two_mock_edks = [mock_edk, mock_edk]

    # Given: ESK lists of various lengths
    for mock_edks in [no_mock_edks, one_mock_edk, two_mock_edks]:

        mock_decryption_materials_request.encrypted_data_keys = mock_edks

        # When: _create_mpl_decrypt_materials_input_from_request
        output = CryptoMaterialsManagerFromMPL._create_mpl_decrypt_materials_input_from_request(
            mock_decryption_materials_request
        )

        # Then:
        # Verify general correctness of output structure
        assert isinstance(output, MPL_DecryptMaterialsInput)
        assert output.algorithm_suite_id == mock_algorithm_id
        assert output.commitment_policy == mock_commitment_policy
        assert output.encryption_context == mock_decryption_materials_request.encryption_context

        assert len(output.encrypted_data_keys) == len(mock_edks)
        for i in range(len(output.encrypted_data_keys)):
            # Assume input[i] == output[i] to make validation easier
            # This is how the src is implemented but is not a requirement.
            # If this assumption breaks, we should enhance this test.
            output_edk = output.encrypted_data_keys[i]
            input_edk = mock_edks[i]
            assert output_edk.key_provider_id == input_edk.key_provider.provider_id
            assert output_edk.key_provider_info == input_edk.key_provider.key_info
            assert output_edk.ciphertext == input_edk.encrypted_data_key
