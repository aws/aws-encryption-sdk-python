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
"""Test suite for aws_encryption_sdk.materials_managers"""
import pytest
from mock import MagicMock
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.materials_managers import (
    DecryptionMaterials,
    DecryptionMaterialsRequest,
    EncryptionMaterials,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.structures import DataKey

pytestmark = [pytest.mark.unit, pytest.mark.local]


_VALID_KWARGS = {
    "EncryptionMaterialsRequest": dict(
        encryption_context={},
        plaintext_rostream=MagicMock(__class__=ROStream),
        frame_length=5,
        algorithm=MagicMock(__class__=Algorithm),
        plaintext_length=5,
    ),
    "EncryptionMaterials": dict(
        algorithm=MagicMock(__class__=Algorithm),
        data_encryption_key=MagicMock(__class__=DataKey),
        encrypted_data_keys=set([]),
        encryption_context={},
        signing_key=b"",
        commitment_policy=MagicMock(__class__=CommitmentPolicy),
    ),
    "DecryptionMaterialsRequest": dict(
        algorithm=MagicMock(__class__=Algorithm),
        encrypted_data_keys=set([]),
        encryption_context={},
    ),
    "DecryptionMaterials": dict(
        data_key=MagicMock(__class__=DataKey),
        verification_key=b"ex_verification_key",
        commitment_policy=MagicMock(__class__=CommitmentPolicy),
    ),
}


@pytest.mark.parametrize(
    "attr_class, invalid_kwargs",
    (
        (EncryptionMaterialsRequest, dict(encryption_context=None)),
        (EncryptionMaterialsRequest, dict(frame_length="not an int")),
        (EncryptionMaterialsRequest, dict(algorithm="not an Algorithm or None")),
        (EncryptionMaterialsRequest, dict(plaintext_length="not an int or None")),
        (EncryptionMaterials, dict(algorithm=None)),
        (EncryptionMaterials, dict(data_encryption_key=None)),
        (EncryptionMaterials, dict(encrypted_data_keys=None)),
        (EncryptionMaterials, dict(encryption_context=None)),
        (EncryptionMaterials, dict(signing_key=u"not bytes or None")),
        (DecryptionMaterialsRequest, dict(algorithm=None)),
        (DecryptionMaterialsRequest, dict(encrypted_data_keys=None)),
        (DecryptionMaterialsRequest, dict(encryption_context=None)),
        (DecryptionMaterials, dict(data_key=None)),
        (DecryptionMaterials, dict(verification_key=5555)),
    ),
)
def test_attributes_fails(attr_class, invalid_kwargs):
    kwargs = _VALID_KWARGS[attr_class.__name__].copy()
    kwargs.update(invalid_kwargs)
    with pytest.raises(TypeError):
        attr_class(**kwargs)


def test_encryption_materials_request_attributes_defaults():
    test = EncryptionMaterialsRequest(
        encryption_context={},
        frame_length=5,
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    )
    assert test.plaintext_rostream is None
    assert test.algorithm is None
    assert test.plaintext_length is None


def test_encryption_materials_defaults():
    test = EncryptionMaterials(
        algorithm=MagicMock(__class__=Algorithm),
        data_encryption_key=MagicMock(__class__=DataKey),
        encrypted_data_keys=set([]),
        encryption_context={},
    )
    assert test.signing_key is None


def test_decryption_materials_defaults():
    test = DecryptionMaterials(data_key=MagicMock(__class__=DataKey))
    assert test.verification_key is None
