# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.materials_managers.mpl.materials logic.

The aws-cryptographic-materials-library MUST be installed to run tests in this module.
"""

import pytest
from aws_cryptographic_material_providers.mpl.models import (
    DecryptionMaterials as MPL_DecryptionMaterials,
    EncryptedDataKey as MPL_EncryptedDataKey,
    EncryptionMaterials as MPL_EncryptionMaterials,
)
from mock import MagicMock, patch
from typing import Dict

import aws_encryption_sdk.materials_managers.mpl.materials
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest
from aws_encryption_sdk.materials_managers.mpl.materials import DecryptionMaterialsFromMPL, EncryptionMaterialsFromMPL

pytestmark = [pytest.mark.unit, pytest.mark.local]


mock_mpl_encryption_materials = MagicMock(__class__=MPL_EncryptionMaterials)
mock_mpl_decrypt_materials = MagicMock(__class__=MPL_DecryptionMaterials)

mock_encryption_materials_request = MagicMock(__class__=EncryptionMaterialsRequest)
mock_encryption_materials_handler = MagicMock(__class__=EncryptionMaterialsFromMPL)
mock_decryption_materials_request = MagicMock(__class__=DecryptionMaterialsRequest)

mock_edk = MagicMock(__class__=MPL_EncryptedDataKey)
mock_mpl_key_provider_id = MagicMock(__class__=str)
mock_edk.key_provider_id = mock_mpl_key_provider_id
mock_mpl_key_provider_info = MagicMock(__class__=bytes)
mock_edk.key_provider_info = mock_mpl_key_provider_info
mock_mpl_ciphertext = MagicMock(__class__=bytes)
mock_edk.ciphertext = mock_mpl_ciphertext


def test_GIVEN_mpl_materials_WHEN_create_EncryptionMaterialsFromMPL_THEN_return_new_CryptoMaterialsManagerFromMPL():
    # Given: valid mpl_materials
    # When: create EncryptionMaterialsFromMPL
    mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)

    # Then: EncryptionMaterialsFromMPL is valid
    assert mpl_encryption_materials.mpl_materials == mock_mpl_encryption_materials


def test_GIVEN_invalid_mpl_materials_WHEN_create_EncryptionMaterialsFromMPL_THEN_raise_ValueError():
    # Then: Raise ValueError
    with pytest.raises(ValueError):
        # Given: invalid mpl_materials
        # When: create EncryptionMaterialsFromMPL
        EncryptionMaterialsFromMPL(mpl_materials="not a valid mpl_materials")


def test_GIVEN_valid_mpl_algorithm_id_WHEN_mpl_algorithm_id_to_native_algorithm_id_THEN_valid_native_output():
    # Given: any valid MPL algorithm ID
    some_mpl_algorithm_id = "0x1234"  # Not a real algorithm ID, but fits the format

    # When: _mpl_algorithm_id_to_native_algorithm_id
    native_output = aws_encryption_sdk.materials_managers.mpl.materials._mpl_algorithm_id_to_native_algorithm_id(
        some_mpl_algorithm_id
    )

    # Then: valid native algorithm ID
    assert native_output == 0x1234


@patch("aws_encryption_sdk.materials_managers.mpl.materials._mpl_algorithm_id_to_native_algorithm_id")
@patch("aws_encryption_sdk.materials_managers.mpl.materials.AlgorithmSuite.get_by_id")
def test_GIVEN_valid_mpl_algorithm_id_WHEN_EncryptionMaterials_get_algorithm_THEN_valid_native_algorithm_id(
    mock_algorithm,
    mock_native_algorithm_id,
):
    # Given: _mpl_algorithm_id_to_native_algorithm_id returns a valid native algorithm ID
    mock_native_algorithm_id.return_value = 0x1234

    # Given: get_by_id returns a valid native AlgorithmSuite by looking up an ID
    mock_algorithm.return_value = MagicMock(__class__=AlgorithmSuite)

    # When: Get algorithm
    mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.algorithm

    # Then: output is valid
    assert output == mock_algorithm()  # property calls automatically, we need to call the mock


def test_GIVEN_valid_encryption_context_WHEN_EncryptionMaterials_get_encryption_context_THEN_valid_encryption_context():
    # Given: valid encryption context
    mock_encryption_context = MagicMock(__class__=Dict[str, str])
    mock_mpl_encryption_materials.encryption_context = mock_encryption_context

    # When: get encryption context
    mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.encryption_context

    # Then: returns valid encryption context
    assert output == mock_encryption_context


def test_GIVEN_valid_edks_WHEN_EncryptionMaterials_get_edks_THEN_returns_edks():

    # Given: lists of mocked EDKs of various lengths
    no_mock_edks = []
    one_mock_edk = [mock_edk]
    two_mocked_edks = [mock_edk, mock_edk]
    for mock_edks in [no_mock_edks, one_mock_edk, two_mocked_edks]:
        mock_mpl_encryption_materials.encrypted_data_keys = mock_edks

        # When: get EDKs
        mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)
        output = mpl_encryption_materials.encrypted_data_keys

        # Then: returns EDKs
        output_as_list = list(output)
        # Native ESDK Python types the EDKs as a set;
        # Ensure the MPL's list is collapsed into a set correctly
        assert len(output_as_list) == len(set(mock_edks))
        for i in range(len(output_as_list)):
            # Assume input[i] == output[i] to make validation easier
            # This is how the src is implemented but is not a requirement.
            # If this assumption breaks, we should enhance this test.
            native_edk = output_as_list[i]
            mpl_edk = mock_edks[i]

            assert native_edk.encrypted_data_key == mpl_edk.ciphertext
            assert native_edk.key_provider.provider_id == mpl_edk.key_provider_id
            assert native_edk.key_provider.key_info == mpl_edk.key_provider_info


def test_GIVEN_valid_data_key_WHEN_EncryptionMaterials_get_data_key_THEN_returns_data_key():
    # Given: Valid MPL data key
    mock_data_key = MagicMock(__class__=bytes)
    mock_mpl_encryption_materials.plaintext_data_key = mock_data_key

    # When: get data key
    mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.data_encryption_key

    # Then: Returns native data key
    assert output.key_provider.provider_id == ""
    assert output.key_provider.key_info == b""
    assert output.data_key == mock_data_key
    assert output.encrypted_data_key == b""


def test_GIVEN_valid_signing_key_WHEN_EncryptionMaterials_get_signing_key_THEN_returns_signing_key():
    # Given: valid signing key
    mock_signing_key = MagicMock(__class__=bytes)
    mock_mpl_encryption_materials.signing_key = mock_signing_key

    # When: get signing key
    mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.signing_key

    # Then: returns signing key
    assert output == mock_signing_key


def test_GIVEN_valid_required_encryption_context_keys_WHEN_EncryptionMaterials_get_required_encryption_context_keys_THEN_returns_required_encryption_context_keys():  # noqa pylint: disable=line-too-long
    # Given: valid required encryption context keys
    mock_required_encryption_context_keys = MagicMock(__class__=bytes)
    mock_mpl_encryption_materials.required_encryption_context_keys = mock_required_encryption_context_keys

    # When: get required encryption context keys
    mpl_encryption_materials = EncryptionMaterialsFromMPL(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.required_encryption_context_keys

    # Then: returns required encryption context keys
    assert output == mock_required_encryption_context_keys


def test_GIVEN_valid_data_key_WHEN_DecryptionMaterials_get_data_key_THEN_returns_data_key():
    # Given: valid MPL data key
    mock_data_key = MagicMock(__class__=bytes)
    mock_mpl_decrypt_materials.plaintext_data_key = mock_data_key

    # When: get data key
    mpl_decryption_materials = DecryptionMaterialsFromMPL(mpl_materials=mock_mpl_decrypt_materials)
    output = mpl_decryption_materials.data_key

    # Then: returns valid native data key
    assert output.key_provider.provider_id == ""
    assert output.key_provider.key_info == b""
    assert output.data_key == mock_data_key
    assert output.encrypted_data_key == b""


def test_GIVEN_valid_verification_key_WHEN_DecryptionMaterials_get_verification_key_THEN_returns_verification_key():
    # Given: valid verification key
    mock_verification_key = MagicMock(__class__=bytes)
    mock_mpl_decrypt_materials.verification_key = mock_verification_key

    # When: get verification key
    mpl_decryption_materials = DecryptionMaterialsFromMPL(mpl_materials=mock_mpl_decrypt_materials)
    output = mpl_decryption_materials.verification_key

    # Then: returns verification key
    assert output == mock_verification_key


def test_GIVEN_valid_encryption_context_WHEN_DecryptionMaterials_get_encryption_context_THEN_returns_encryption_context():  # noqa pylint: disable=line-too-long
    # Given: valid encryption context
    mock_encryption_context = MagicMock(__class__=Dict[str, str])
    mock_mpl_decrypt_materials.encryption_context = mock_encryption_context

    # When: get encryption context
    mpl_decryption_materials = DecryptionMaterialsFromMPL(mpl_materials=mock_mpl_decrypt_materials)
    output = mpl_decryption_materials.encryption_context

    # Then: returns valid encryption context
    assert output == mock_encryption_context


def test_GIVEN_valid_required_encryption_context_keys_WHEN_DecryptionMaterials_get_required_encryption_context_keys_THEN_returns_required_encryption_context_keys():  # noqa pylint: disable=line-too-long
    # Given: valid required encryption context keys
    mock_required_encryption_context_keys = MagicMock(__class__=bytes)
    mock_mpl_decrypt_materials.required_encryption_context_keys = mock_required_encryption_context_keys

    # When: get required encryption context keys
    mpl_decryption_materials = DecryptionMaterialsFromMPL(mpl_materials=mock_mpl_decrypt_materials)
    output = mpl_decryption_materials.required_encryption_context_keys

    # Then: returns required encryption context keys
    assert output == mock_required_encryption_context_keys
