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
"""Unit test suite to validate aws_encryption_sdk.key_providers.raw.RawMasterKeyConfig"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyConfig


def test_parent():
    assert issubclass(RawMasterKeyConfig, MasterKeyConfig)


@pytest.mark.parametrize('attribute, default, validator_type, convert_function', (
    (RawMasterKeyConfig.provider_id, attr.NOTHING, (six.string_types, bytes), to_str),
    (RawMasterKeyConfig.wrapping_key, attr.NOTHING, WrappingKey, None)
))
def test_attributes(attribute, default, validator_type, convert_function):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    assert attribute.default is default
    assert attribute.validator.type == validator_type
    if convert_function is not None:
        assert attribute.convert is convert_function


def test_attributes_fails():
    with pytest.raises(TypeError):
        RawMasterKeyConfig(wrapping_key=None)


@pytest.mark.parametrize('provider_id', ('test', b'test'))
def test_attributes_convertss(provider_id):
    test = RawMasterKeyConfig(
        key_id='',
        provider_id=provider_id,
        wrapping_key=MagicMock(__class__=WrappingKey)
    )
    assert test.provider_id == 'test'
