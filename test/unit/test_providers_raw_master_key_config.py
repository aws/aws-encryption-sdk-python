# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.key_providers.raw.RawMasterKeyConfig"""
import pytest
import six

from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyConfig

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs

pytestmark = [pytest.mark.unit, pytest.mark.local]

STATIC_WRAPPING_KEY = WrappingKey(
    wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    wrapping_key=b"_________a symmetric key________",
    wrapping_key_type=EncryptionKeyType.SYMMETRIC,
)
VALID_KWARGS = {
    RawMasterKeyConfig: [
        dict(key_id=b"a raw key", provider_id="a provider", wrapping_key=STATIC_WRAPPING_KEY),
        dict(key_id=b"a raw key", provider_id=b"a provider", wrapping_key=STATIC_WRAPPING_KEY),
    ]
}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


def test_parent():
    assert issubclass(RawMasterKeyConfig, MasterKeyConfig)


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_converts(cls, kwargs):
    test = cls(**kwargs)
    assert isinstance(test.provider_id, six.string_types)
