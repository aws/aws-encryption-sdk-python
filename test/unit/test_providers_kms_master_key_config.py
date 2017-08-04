"""Unit test suite to validate aws_encryption_sdk.key_providers.kms.KMSMasterKeyConfig"""
import attr
import botocore.client
from mock import MagicMock, sentinel
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyConfig, _PROVIDER_ID


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
