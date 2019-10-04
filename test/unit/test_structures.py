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
"""Unit test suite for aws_encryption_sdk.structures"""
import pytest

from aws_encryption_sdk.identifiers import Algorithm, ContentType, ObjectType, SerializationVersion
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo, MessageHeader, RawDataKey

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs

pytestmark = [pytest.mark.unit, pytest.mark.local]


VALID_KWARGS = {
    MessageHeader: [
        dict(
            version=SerializationVersion.V1,
            type=ObjectType.CUSTOMER_AE_DATA,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            message_id=b"aosiejfoaiwej",
            encryption_context={},
            encrypted_data_keys=set([]),
            content_type=ContentType.FRAMED_DATA,
            content_aad_length=32456,
            header_iv_length=32456,
            frame_length=234567,
        )
    ],
    MasterKeyInfo: [
        dict(provider_id="fawnofijawef", key_info="ajsnoiajerofi"),
        dict(provider_id=b"fawnofijawef", key_info="ajsnoiajerofi"),
        dict(provider_id="fawnofijawef", key_info=b"ajsnoiajerofi"),
        dict(provider_id=b"fawnofijawef", key_info=b"ajsnoiajerofi"),
    ],
    RawDataKey: [
        dict(key_provider=MasterKeyInfo(provider_id="asjnoa", key_info=b"aosjfoaiwej"), data_key=b"aosijfoewaijf")
    ],
    DataKey: [
        dict(
            key_provider=MasterKeyInfo(provider_id="asjnoa", key_info=b"aosjfoaiwej"),
            data_key=b"oaijefoawiejf",
            encrypted_data_key=b"aisofiawjef",
        )
    ],
    EncryptedDataKey: [
        dict(
            key_provider=MasterKeyInfo(provider_id="asjnoa", key_info=b"aosjfoaiwej"), encrypted_data_key=b"aisofiawjef"
        )
    ],
}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


@pytest.mark.parametrize(
    "kwargs, attribute, expected_value",
    (
        (dict(provider_id="asfoijwae", key_info=b"oaiejfoeiwja"), "provider_id", "asfoijwae"),
        (dict(provider_id=b"asfoijwae", key_info=b"oaiejfoeiwja"), "provider_id", "asfoijwae"),
        (dict(provider_id="asfoijwae", key_info="oaiejfoeiwja"), "key_info", b"oaiejfoeiwja"),
        (dict(provider_id="asfoijwae", key_info=b"oaiejfoeiwja"), "key_info", b"oaiejfoeiwja"),
    ),
)
def test_master_key_info_convert(kwargs, attribute, expected_value):
    test = MasterKeyInfo(**kwargs)

    assert getattr(test, attribute) == expected_value


@pytest.mark.parametrize(
    "cls, params",
    (
        (DataKey, ("key_provider", "data_key", "encrypted_data_key")),
        (RawDataKey, ("key_provider", "data_key")),
        (EncryptedDataKey, ("key_provider", "encrypted_data_key")),
    ),
)
def test_data_key_repr_str(cls, params):
    data_key = b"plaintext data key ioasuwenvfiuawehnviuawh\x02\x99sd"
    encrypted_data_key = b"encrypted data key josaidejoawuief\x02\x99sd"
    base_params = dict(
        key_provider=MasterKeyInfo(provider_id="asdf", key_info=b"fdsa"),
        data_key=data_key,
        encrypted_data_key=encrypted_data_key,
    )
    test = cls(**{key: base_params[key] for key in params})
    data_key_check = repr(data_key)[2:-1]

    assert data_key_check not in str(test)
    assert data_key_check not in repr(test)


@pytest.fixture
def ex_data_key():
    return DataKey(**VALID_KWARGS[DataKey][0])


def test_encrypted_data_key_from_data_key_success(ex_data_key):
    test = EncryptedDataKey.from_data_key(ex_data_key)

    assert test.key_provider == ex_data_key.key_provider
    assert test.encrypted_data_key == ex_data_key.encrypted_data_key


def test_raw_data_key_from_data_key_success(ex_data_key):
    test = RawDataKey.from_data_key(ex_data_key)

    assert test.key_provider == ex_data_key.key_provider
    assert test.data_key == ex_data_key.data_key


@pytest.mark.parametrize("data_key_class", (EncryptedDataKey, RawDataKey))
def test_raw_and_encrypted_data_key_from_data_key_fail(data_key_class):
    with pytest.raises(TypeError) as excinfo:
        data_key_class.from_data_key(b"ahjseofij")

    excinfo.match(r"data_key must be type DataKey not *")
