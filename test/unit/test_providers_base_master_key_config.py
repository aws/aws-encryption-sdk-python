# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.key_providers.base.MasterKeyConfig"""
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyConfig

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs

pytestmark = [pytest.mark.unit, pytest.mark.local]


class FakeMasterKeyConfig(MasterKeyConfig):
    provider_id = None


VALID_KWARGS = {FakeMasterKeyConfig: [dict(key_id="a key id"), dict(key_id=b"a key id")]}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


@pytest.mark.parametrize("key_id", (b"key", "key"))
def test_attributes_converts(key_id):
    test = FakeMasterKeyConfig(key_id=key_id)
    assert isinstance(test.key_id, bytes)


def test_provider_id_enforcement():
    class TestConfig(MasterKeyConfig):
        pass

    with pytest.raises(TypeError) as excinfo:
        TestConfig(key_id="a key")

    excinfo.match(r'Instances of MasterKeyConfig must have a "provider_id" attribute defined.')
