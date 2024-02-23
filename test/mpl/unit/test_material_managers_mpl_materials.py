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
from mock import MagicMock, patch, PropertyMock
from typing import Dict, List

from aws_encryption_sdk.identifiers import CommitmentPolicy
import aws_encryption_sdk.materials_managers.mpl.materials
from aws_encryption_sdk.materials_managers.mpl.materials import (
    MPLEncryptionMaterials,
    MPLDecryptionMaterials,
)
from aws_encryption_sdk.identifiers import Algorithm, AlgorithmSuite

pytestmark = [pytest.mark.unit, pytest.mark.local]


from aws_cryptographic_materialproviders.mpl.errors import AwsCryptographicMaterialProvidersException
from aws_cryptographic_materialproviders.mpl.models import (
    AlgorithmSuiteIdESDK,
    CommitmentPolicyESDK,
    DecryptMaterialsInput,
    DecryptionMaterials as MPL_DecryptionMaterials,
    EncryptedDataKey as MPL_EncryptedDataKey,
    EncryptionMaterials as MPL_EncryptionMaterials,
    GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
)
from aws_cryptographic_materialproviders.mpl.references import (
    ICryptographicMaterialsManager
)

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
    mpl_encryption_materials = MPLEncryptionMaterials(mpl_materials=mock_mpl_encryption_materials)
    
    assert mpl_encryption_materials.mpl_materials == mock_mpl_encryption_materials


def test_GIVEN_test_has_mpl_is_False_WHEN_create_MPLCMMHandler_with_invalid_mpl_cmm_THEN_raise_ValueError():
    with pytest.raises(ValueError):
        MPLEncryptionMaterials(mpl_materials="not a valid mpl_materials")

def test_mpl_to_native():
    some_mpl_algorithm_id = "0x1234"  # Not a real algorithm ID, but fits the format

    native_output = aws_encryption_sdk.materials_managers.mpl.materials._mpl_algorithm_id_to_native_algorithm_id(
        some_mpl_algorithm_id
    )

    assert native_output == 0x1234


@patch("aws_encryption_sdk.materials_managers.mpl.materials._mpl_algorithm_id_to_native_algorithm_id")
@patch("aws_encryption_sdk.materials_managers.mpl.materials.AlgorithmSuite.get_by_id")
def test_GIVEN_valid_mpl_algorithm_id_WHEN_get_algorithm_THEN_valid_native_algorithm_id(
    mock_algorithm,
    mock_native_algorithm_id,
):
    # Mock valid conversion from MPL to native algorithm ID
    mock_native_algorithm_id.return_value = 0x1234

    # Mock valid lookup in native AlgorithmSuite lookup
    mock_algorithm.return_value = MagicMock(__class__=AlgorithmSuite)

    mpl_encryption_materials = MPLEncryptionMaterials(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.algorithm
    assert output == mock_algorithm()  # property calls automatically, we need to call the mock


def test_GecTHEN_valid_native_algorithm_id():
    mock_encryption_context = MagicMock(__class__=Dict[str, str])
    mock_mpl_encryption_materials.encryption_context = mock_encryption_context

    mpl_encryption_materials = MPLEncryptionMaterials(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.encryption_context

    assert output == mock_encryption_context


def test_GecTHEN_valid_nativefadsf_algorithm_id():
    mock_edk = MagicMock(__class__=MPL_EncryptedDataKey)
    mock_mpl_key_provider_id = MagicMock(__class__=str)
    mock_edk.key_provider_id = mock_mpl_key_provider_id
    mock_mpl_key_provider_info = MagicMock(__class__=bytes)
    mock_edk.key_provider_info = mock_mpl_key_provider_info
    mock_mpl_ciphertext = MagicMock(__class__=bytes)
    mock_edk.ciphertext = mock_mpl_ciphertext

    mock_edks = [ mock_edk ]
    mock_mpl_encryption_materials.encrypted_data_keys = mock_edks

    mpl_encryption_materials = MPLEncryptionMaterials(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.encrypted_data_keys
    output_as_list = list(output)

    assert len(output_as_list) == len(mock_edks)
    for i in range(len(output_as_list)):
        # assume output[i] corresponds to input[i]
        native_edk = output_as_list[i]
        mpl_edk = mock_edks[i]

        assert native_edk.encrypted_data_key == mpl_edk.ciphertext
        assert native_edk.key_provider.provider_id == mpl_edk.key_provider_id
        assert native_edk.key_provider.key_info == mpl_edk.key_provider_info

def test_GecTHEN_valid_nativefadsffadsfa_algorithm_id():
    mock_data_key = MagicMock(__class__=bytes)
    mock_mpl_encryption_materials.plaintext_data_key = mock_data_key

    mpl_encryption_materials = MPLEncryptionMaterials(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.data_encryption_key

    assert output.key_provider.provider_id == ""
    assert output.key_provider.key_info == b""
    assert output.data_key == mock_data_key
    assert output.encrypted_data_key == b""


def test_GecTHEN_valid_nativefasdfasdffadsf_algorithm_id():
    mock_signing_key = MagicMock(__class__=bytes)
    mock_mpl_encryption_materials.signing_key = mock_signing_key

    mpl_encryption_materials = MPLEncryptionMaterials(mpl_materials=mock_mpl_encryption_materials)
    output = mpl_encryption_materials.signing_key

    assert output == mock_signing_key


def test_GecTHEN_valid_nativeffasdfasdadsffadsfa_algorithm_id():
    mock_data_key = MagicMock(__class__=bytes)
    mock_mpl_decrypt_materials.plaintext_data_key = mock_data_key

    mpl_decryption_materials = MPLDecryptionMaterials(mpl_materials=mock_mpl_decrypt_materials)
    output = mpl_decryption_materials.data_key

    assert output.key_provider.provider_id == ""
    assert output.key_provider.key_info == b""
    assert output.data_key == mock_data_key
    assert output.encrypted_data_key == b""


def test_GecTHEN_validadsfasdf_nativefasdfasdffadsf_algorithm_id():
    mock_verification_key = MagicMock(__class__=bytes)
    mock_mpl_decrypt_materials.verification_key = mock_verification_key

    mpl_decryption_materials = MPLDecryptionMaterials(mpl_materials=mock_mpl_decrypt_materials)
    output = mpl_decryption_materials.verification_key

    assert output == mock_verification_key
