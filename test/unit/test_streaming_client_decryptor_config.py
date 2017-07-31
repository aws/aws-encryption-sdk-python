"""Unit test suite to validate aws_encryption_sdk.streaming_client.DecryptorConfig"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.streaming_client import DecryptorConfig, _ClientConfig
from aws_encryption_sdk.key_providers.base import MasterKeyProvider


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
