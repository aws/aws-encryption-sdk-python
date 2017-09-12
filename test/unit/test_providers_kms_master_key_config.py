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
"""Unit test suite to validate aws_encryption_sdk.key_providers.kms.KMSMasterKeyConfig"""
import attr
import botocore.client
from mock import MagicMock, sentinel
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.kms import _PROVIDER_ID, KMSMasterKeyConfig


def test_parent():
    assert issubclass(KMSMasterKeyConfig, MasterKeyConfig)


@pytest.mark.parametrize('attribute, default, validator_type, convert_function', (
    (KMSMasterKeyConfig.client, attr.NOTHING, botocore.client.BaseClient, None),
    (KMSMasterKeyConfig.grant_tokens, attr.Factory(tuple), tuple, tuple)
))
def test_attributes(attribute, default, validator_type, convert_function):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    assert attribute.default == default
    assert attribute.validator.type == validator_type
    if convert_function is not None:
        assert attribute.convert is convert_function


@pytest.mark.parametrize('attribute, value', (
    (KMSMasterKeyConfig.provider_id, _PROVIDER_ID),
))
def test_static_attributes(attribute, value):
    assert attribute == value


def test_attributes_fail():
    with pytest.raises(TypeError):
        KMSMasterKeyConfig(key_id='', client=None)


def test_attributes_defaults():
    test = KMSMasterKeyConfig(
        key_id='',
        client=MagicMock(__class__=botocore.client.BaseClient)
    )
    assert test.grant_tokens == ()


def test_attributes_converts():
    test = KMSMasterKeyConfig(
        key_id='',
        client=MagicMock(__class__=botocore.client.BaseClient),
        grant_tokens=[sentinel.token_1, sentinel.token_2]
    )
    assert test.grant_tokens == (sentinel.token_1, sentinel.token_2)
