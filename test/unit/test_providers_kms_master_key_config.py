# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.key_providers.kms.KMSMasterKeyConfig"""
import boto3
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.kms import _PROVIDER_ID, KMSMasterKeyConfig

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs

pytestmark = [pytest.mark.unit, pytest.mark.local]


VALID_KWARGS = {
    KMSMasterKeyConfig: [
        dict(key_id=b"a cmk", client=boto3.client("kms", region_name="us-west-2"), grant_tokens=()),
        dict(key_id=b"a cmk", client=boto3.client("kms", region_name="us-west-2"), grant_tokens=[]),
        dict(key_id=b"a cmk", client=boto3.client("kms", region_name="us-west-2")),
    ]
}
INVALID_KWARGS = {KMSMasterKeyConfig: [dict(client=None)]}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS, INVALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


def test_parent():
    assert issubclass(KMSMasterKeyConfig, MasterKeyConfig)


@pytest.mark.parametrize("attribute, value", ((KMSMasterKeyConfig.provider_id, _PROVIDER_ID),))
def test_static_attributes(attribute, value):
    assert attribute == value


def test_attributes_defaults():
    test = KMSMasterKeyConfig(key_id=b"a cmk", client=boto3.client("kms", region_name="us-west-2"))
    assert test.grant_tokens == ()


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_converts(cls, kwargs):
    test = cls(**kwargs)
    assert isinstance(test.grant_tokens, tuple)
