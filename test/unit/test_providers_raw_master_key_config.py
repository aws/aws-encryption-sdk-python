"""Unit test suite to validate aws_encryption_sdk.key_providers.raw.RawMasterKeyConfig"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.internal.crypto import WrappingKey
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
