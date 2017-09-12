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
"""Unit test suite to validate aws_encryption_sdk.streaming_client.EncryptorConfig"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.defaults import FRAME_LENGTH
from aws_encryption_sdk.key_providers.base import MasterKey
from aws_encryption_sdk.streaming_client import _ClientConfig, EncryptorConfig


def test_parent():
    assert issubclass(EncryptorConfig, _ClientConfig)


@pytest.mark.parametrize('attribute, default, validator_type, in_hash, is_optional', (
    (EncryptorConfig.encryption_context, attr.Factory(dict), dict, False, False),
    (EncryptorConfig.algorithm, None, Algorithm, True, True),
    (EncryptorConfig.frame_length, FRAME_LENGTH, six.integer_types, True, False)
))
def test_attributes(attribute, default, validator_type, in_hash, is_optional):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.default == default
    if is_optional:
        assert attribute.validator.validator.type == validator_type
    else:
        assert attribute.validator.type == validator_type
    if in_hash:
        assert attribute.hash
    else:
        assert not attribute.hash


@pytest.mark.parametrize('encryption_context, frame_length', (
    (None, 5),
    ({}, None)
))
def test_attributes_fail(encryption_context, frame_length):
    with pytest.raises(TypeError):
        EncryptorConfig(
            source='',
            key_provider=MagicMock(__class__=MasterKey),
            encryption_context=encryption_context,
            algorithm=MagicMock(__class__=Algorithm),
            frame_length=frame_length
        )


def test_attributes_defaults():
    test = EncryptorConfig(source='', key_provider=MagicMock(__class__=MasterKey))
    assert test.encryption_context == {}
    assert test.algorithm is None
    assert test.frame_length == FRAME_LENGTH
