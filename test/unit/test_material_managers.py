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
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk.identifiers import KeyRingTraceFlag
from aws_encryption_sdk.internal.defaults import ALGORITHM
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.materials_managers import (
    CryptographicMaterials,
    DecryptionMaterials,
    DecryptionMaterialsRequest,
    EncryptionMaterials,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.structures import DataKey, KeyRingTrace, MasterKeyInfo

pytestmark = [pytest.mark.unit, pytest.mark.local]

_DATA_KEY = DataKey(
    key_provider=MasterKeyInfo(provider_id="Provider", key_info=b"Info"),
    data_key=b"1234567890123456789012",
    encrypted_data_key=b"asdf",
)

_VALID_KWARGS = {
    "CryptographicMaterials": dict(
        algorithm=ALGORITHM,
        encryption_context={"additional": "data"},
        data_encryption_key=_DATA_KEY,
        encrypted_data_keys=[],
        keyring_trace=[
            KeyRingTrace(
                wrapping_key=MasterKeyInfo(provider_id="Provider", key_info=b"Info"),
                flags={KeyRingTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
            )
        ],
    ),
    "EncryptionMaterialsRequest": dict(
        encryption_context={},
        plaintext_rostream=MagicMock(__class__=ROStream),
        frame_length=5,
        algorithm=ALGORITHM,
        plaintext_length=5,
    ),
    "EncryptionMaterials": dict(
        algorithm=ALGORITHM,
        data_encryption_key=_DATA_KEY,
        encrypted_data_keys=set([]),
        encryption_context={},
        signing_key=b"",
    ),
    "DecryptionMaterialsRequest": dict(algorithm=ALGORITHM, encrypted_data_keys=set([]), encryption_context={}),
    "DecryptionMaterials": dict(
        data_key=_DATA_KEY, verification_key=b"ex_verification_key", algorithm=ALGORITHM, encryption_context={}
    ),
}
_REMOVE = object()


@pytest.mark.parametrize(
    "attr_class, invalid_kwargs",
    (
        (CryptographicMaterials, dict(algorithm=1234)),
        (CryptographicMaterials, dict(encryption_context=1234)),
        (CryptographicMaterials, dict(data_encryption_key=1234)),
        (CryptographicMaterials, dict(encrypted_data_keys=1234)),
        (CryptographicMaterials, dict(keyring_trace=1234)),
        (EncryptionMaterialsRequest, dict(encryption_context=None)),
        (EncryptionMaterialsRequest, dict(frame_length="not an int")),
        (EncryptionMaterialsRequest, dict(algorithm="not an Algorithm or None")),
        (EncryptionMaterialsRequest, dict(plaintext_length="not an int or None")),
        (EncryptionMaterials, dict(algorithm=None)),
        (EncryptionMaterials, dict(encryption_context=None)),
        (EncryptionMaterials, dict(signing_key=u"not bytes or None")),
        (DecryptionMaterialsRequest, dict(algorithm=None)),
        (DecryptionMaterialsRequest, dict(encrypted_data_keys=None)),
        (DecryptionMaterialsRequest, dict(encryption_context=None)),
        (DecryptionMaterials, dict(verification_key=5555)),
        (DecryptionMaterials, dict(data_key=_DATA_KEY, data_encryption_key=_DATA_KEY)),
        (DecryptionMaterials, dict(data_key=_REMOVE, data_encryption_key=_REMOVE)),
    ),
)
def test_attributes_fails(attr_class, invalid_kwargs):
    kwargs = _VALID_KWARGS[attr_class.__name__].copy()
    kwargs.update(invalid_kwargs)
    purge_keys = [key for key, val in kwargs.items() if val is _REMOVE]
    for key in purge_keys:
        del kwargs[key]
    with pytest.raises(TypeError):
        attr_class(**kwargs)


def test_encryption_materials_request_attributes_defaults():
    test = EncryptionMaterialsRequest(encryption_context={}, frame_length=5)
    assert test.plaintext_rostream is None
    assert test.algorithm is None
    assert test.plaintext_length is None


def test_encryption_materials_defaults():
    test = EncryptionMaterials(
        algorithm=ALGORITHM, data_encryption_key=_DATA_KEY, encrypted_data_keys=set([]), encryption_context={}
    )
    assert test.signing_key is None


def test_decryption_materials_defaults():
    test = DecryptionMaterials(data_key=_DATA_KEY)
    assert test.verification_key is None
    assert test.algorithm is None
    assert test.encryption_context is None


def test_decryption_materials_legacy_data_key_get():
    test = DecryptionMaterials(data_encryption_key=_DATA_KEY)

    assert test.data_encryption_key is _DATA_KEY
    assert test.data_key is _DATA_KEY


def test_decryption_materials_legacy_data_key_set():
    test = DecryptionMaterials(data_encryption_key=_DATA_KEY)

    test.data_key = sentinel.data_key

    assert test.data_encryption_key is sentinel.data_key
    assert test.data_key is sentinel.data_key
