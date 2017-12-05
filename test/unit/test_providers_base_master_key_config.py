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
"""Unit test suite to validate aws_encryption_sdk.key_providers.base.MasterKeyConfig"""
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs


class FakeMasterKeyConfig(MasterKeyConfig):
    provider_id = None


VALID_KWARGS = {
    FakeMasterKeyConfig: [
        dict(key_id='a key id'),
        dict(key_id=b'a key id')
    ]
}


@pytest.mark.parametrize('cls, kwargs', all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize('cls, kwargs', all_invalid_kwargs(VALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


@pytest.mark.parametrize('key_id', (b'key', 'key'))
def test_attributes_converts(key_id):
    test = FakeMasterKeyConfig(key_id=key_id)
    assert isinstance(test.key_id, bytes)


def test_provider_id_enforcement():
    class TestConfig(MasterKeyConfig):
        pass

    with pytest.raises(TypeError) as excinfo:
        TestConfig(key_id='a key')

    excinfo.match(r'Instances of MasterKeyConfig must have a "provider_id" attribute defined.')
