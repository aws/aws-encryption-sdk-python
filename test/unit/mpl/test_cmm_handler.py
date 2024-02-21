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
"""Test suite to verify the cmm_handler module delegates correctly."""
import pytest
from aws_cryptographic_materialproviders.mpl.models import (
    EncryptionMaterials as MPL_EncryptionMaterials,
    GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
)
from aws_cryptographic_materialproviders.mpl.references import ICryptographicMaterialsManager
from mock import MagicMock, patch

from aws_encryption_sdk.internal.mpl.cmm_handler import CMMHandler
from aws_encryption_sdk.internal.mpl.materials_handlers import EncryptionMaterialsHandler
from aws_encryption_sdk.materials_managers import (
    EncryptionMaterials as Native_EncryptionMaterials,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

mock_native_cmm = MagicMock(__class__=CryptoMaterialsManager)
mock_mpl_cmm = MagicMock(__class__=ICryptographicMaterialsManager)
mock_encryption_materials_request = MagicMock(__class__=EncryptionMaterialsRequest)
mock_encryption_materials_handler = MagicMock(__class__=EncryptionMaterialsHandler)
mock_native_encryption_materials = MagicMock(__class__=Native_EncryptionMaterials)
mock_mpl_encryption_materials = MagicMock(__class__=MPL_EncryptionMaterials)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_GIVEN_native_CMM_WHEN_create_CMMHandler_THEN_is_using_native_cmm_returns_True():
    cmm_handler = CMMHandler(cmm=mock_native_cmm)
    assert cmm_handler._is_using_native_cmm()


def test_GIVEN_mpl_CMM_WHEN_create_CMMHandler_THEN_is_using_native_cmm_returns_False():
    cmm_handler = CMMHandler(cmm=mock_mpl_cmm)
    assert not cmm_handler._is_using_native_cmm()


def test_GIVEN_unknown_CMM_WHEN_create_CMMHandler_THEN_raise_ValueError():
    with pytest.raises(ValueError):
        CMMHandler(cmm="not a CMM")


@patch.object(mock_native_cmm, "get_encryption_materials")
def test_GIVEN_native_CMM_WHEN_get_encryption_materials_THEN_return_native_encryption_materials(
    mock_get_encryption_materials
):
    # Mock: native_cmm.get_encryption_materials returns mock native encryption materials
    mock_get_encryption_materials.return_value = mock_native_encryption_materials

    cmm_handler = CMMHandler(cmm=mock_native_cmm)
    test = cmm_handler.get_encryption_materials(mock_encryption_materials_request)

    # Verify cmm_handler returns EncryptionMaterialsHandler
    assert isinstance(test, EncryptionMaterialsHandler)
    # Verify returned EncryptionMaterialsHandler uses the output of `get_encryption_materials`
    assert test.native_materials == mock_native_encryption_materials
    # Verify we actually called `get_encryption_materials`
    mock_native_cmm.get_encryption_materials.assert_called_once_with(mock_encryption_materials_request)


@patch.object(mock_mpl_cmm, "get_encryption_materials")
@patch("aws_encryption_sdk.internal.mpl.cmm_handler.CMMHandler._native_to_mpl_get_encryption_materials")
def test_GIVEN_mpl_CMM_WHEN_get_encryption_materials_THEN_return_mpl_encryption_materials(
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

    cmm_handler = CMMHandler(cmm=mock_mpl_cmm)
    test = cmm_handler.get_encryption_materials(mock_encryption_materials_request)

    # Verify cmm_handler returns EncryptionMaterialsHandler
    assert isinstance(test, EncryptionMaterialsHandler)
    # Verify returned EncryptionMaterialsHandler uses the output of `get_encryption_materials`
    assert test.mpl_materials == mock_mpl_encryption_materials
    # Verify we actually called `get_encryption_materials`
    mock_mpl_cmm.get_encryption_materials.assert_called_once_with(mock_get_encryption_materials_input)
