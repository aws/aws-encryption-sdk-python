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
"""Unit test suite to validate aws_encryption_sdk.streaming_client.DecryptorConfig"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.streaming_client import _ClientConfig, DecryptorConfig


def test_parent():
    assert issubclass(DecryptorConfig, _ClientConfig)


@pytest.mark.parametrize('attribute, default, validator_type, is_optional', (
    (DecryptorConfig.max_body_length, None, six.integer_types, True),
))
def test_attributes(attribute, default, validator_type, is_optional):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    assert attribute.default == default
    if is_optional:
        assert attribute.validator.validator.type == validator_type
    else:
        assert attribute.validator.type == validator_type


def test_attributes_fails():
    with pytest.raises(TypeError):
        DecryptorConfig(
            source='',
            key_provider=MagicMock(__class__=MasterKeyProvider),
            max_body_length='not an int'
        )


def test_attributes_defaults():
    test = DecryptorConfig(
        source='',
        key_provider=MagicMock(__class__=MasterKeyProvider)
    )
    assert test.max_body_length is None
