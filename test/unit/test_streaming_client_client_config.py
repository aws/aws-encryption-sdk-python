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
"""Unit test suite to validate aws_encryption_sdk.streaming_client._ClientConfig"""
import io

import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.internal.defaults import LINE_LENGTH
from aws_encryption_sdk.internal.utils import prep_stream_data
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.streaming_client import _ClientConfig


@pytest.mark.parametrize('attribute, default, validator_type, is_optional, convert_function', (
    (_ClientConfig.source, attr.NOTHING, None, False, prep_stream_data),
    (_ClientConfig.key_provider, None, MasterKeyProvider, True, None),
    (_ClientConfig.materials_manager, None, CryptoMaterialsManager, True, None),
    (_ClientConfig.source_length, None, six.integer_types, True, None),
    (_ClientConfig.line_length, LINE_LENGTH, six.integer_types, False, None)
))
def test_attributes(attribute, default, validator_type, is_optional, convert_function):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    assert attribute.default is default
    if validator_type is not None:
        if is_optional:
            assert attribute.validator.validator.type == validator_type
        else:
            assert attribute.validator.type == validator_type
    if convert_function is not None:
        assert attribute.convert is convert_function


@pytest.mark.parametrize('key_provider, materials_manager, source_length', (
    (None, None, 5),
    (MagicMock(__class__=MasterKeyProvider), None, 'not an int'),
    (None, MagicMock(__class__=CryptoMaterialsManager), 'not an int'),
    (MagicMock(__class__=MasterKeyProvider), MagicMock(__class__=CryptoMaterialsManager), 5)
))
def test_attributes_fail(key_provider, materials_manager, source_length):
    with pytest.raises(TypeError):
        _ClientConfig(
            source='',
            key_provider=key_provider,
            materials_manager=materials_manager,
            source_length=source_length
        )


def test_attributes_defaults():
    test = _ClientConfig(
        source='',
        key_provider=MagicMock(__class__=MasterKeyProvider)
    )
    assert test.source_length is None
    assert test.line_length == LINE_LENGTH


def test_attributes_converts():
    test = _ClientConfig(
        source='',
        key_provider=MagicMock(__class__=MasterKeyProvider)
    )
    assert isinstance(test.source, io.BytesIO)
    assert isinstance(test.materials_manager, DefaultCryptoMaterialsManager)
    assert test.materials_manager.master_key_provider is test.key_provider
