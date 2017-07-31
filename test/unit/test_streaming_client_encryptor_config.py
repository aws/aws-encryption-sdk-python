"""Unit test suite to validate aws_encryption_sdk.streaming_client.EncryptorConfig"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.internal.defaults import FRAME_LENGTH
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.streaming_client import EncryptorConfig, _ClientConfig
from aws_encryption_sdk.key_providers.base import MasterKey


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
