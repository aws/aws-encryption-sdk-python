"""Unit test suite to validate aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig"""
import attr
import botocore.session
from mock import MagicMock, sentinel
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProviderConfig


def test_parent():
    assert issubclass(KMSMasterKeyProviderConfig, MasterKeyProviderConfig)


@pytest.mark.parametrize('attribute, default, validator_type, convert_function', (
    (KMSMasterKeyProviderConfig.botocore_session, attr.Factory(botocore.session.Session), botocore.session.Session, None),
    (KMSMasterKeyProviderConfig.key_ids, attr.Factory(tuple), tuple, tuple),
    (KMSMasterKeyProviderConfig.region_names, attr.Factory(tuple), tuple, tuple)
))
def test_attributes(attribute, default, validator_type, convert_function):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    assert attribute.default == default
    assert attribute.validator.type == validator_type
    if convert_function is not None:
        assert attribute.convert is convert_function


def test_attributes_fails():
    with pytest.raises(TypeError):
        KMSMasterKeyProviderConfig(botocore_session=None)


def test_attributes_converts():
    test = KMSMasterKeyProviderConfig(
        botocore_session=MagicMock(__class__=botocore.session.Session),
        key_ids=[sentinel.key_a, sentinel.key_b],
        region_names=[sentinel.region_a, sentinel.region_b]
    )
    assert test.key_ids == (sentinel.key_a, sentinel.key_b)
    assert test.region_names == (sentinel.region_a, sentinel.region_b)


def test_attributes_defaults():
    test = KMSMasterKeyProviderConfig()
    assert isinstance(test.botocore_session, botocore.session.Session)
    assert test.key_ids == ()
    assert test.region_names == ()
