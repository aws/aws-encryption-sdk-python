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
import attr
from mock import sentinel
import pytest
import six

from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.key_providers.base import MasterKeyConfig


@pytest.mark.parametrize('attribute, validator_type, convert_function', (
    (MasterKeyConfig.key_id, (six.string_types, bytes), to_bytes),
))
def test_attributes(attribute, validator_type, convert_function):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    assert attribute.validator.type == validator_type
    assert attribute.convert is convert_function


def test_attributes_fails():
    class TestConfig(MasterKeyConfig):
        provider_id = sentinel.provider_id
    with pytest.raises(TypeError):
        TestConfig(key_id=None)


@pytest.mark.parametrize('key_id', (b'key', 'key'))
def test_attributes_converts(key_id):
    class TestConfig(MasterKeyConfig):
        provider_id = sentinel.provider_id
    test = TestConfig(key_id=key_id)
    assert isinstance(test.key_id, bytes)


def test_provider_id_enforcement():
    class TestConfig(MasterKeyConfig):
        pass

    with pytest.raises(TypeError) as excinfo:
        TestConfig()

    excinfo.match(r"Can't instantiate abstract class TestConfig *")
