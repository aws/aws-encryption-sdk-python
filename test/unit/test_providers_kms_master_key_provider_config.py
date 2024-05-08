# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig"""
import botocore.session
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProviderConfig

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs

pytestmark = [pytest.mark.unit, pytest.mark.local]


VALID_KWARGS = {
    KMSMasterKeyProviderConfig: [
        dict(botocore_session=botocore.session.Session(), key_ids=(), region_names=()),
        dict(botocore_session=botocore.session.Session(), key_ids=[], region_names=()),
        dict(botocore_session=botocore.session.Session(), key_ids=(), region_names=[]),
        dict(botocore_session=botocore.session.Session(), region_names=()),
        dict(botocore_session=botocore.session.Session(), key_ids=()),
        dict(botocore_session=botocore.session.Session()),
    ]
}
INVALID_KWARGS = {KMSMasterKeyProviderConfig: [dict(botocore_session=None)]}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS, INVALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


def test_parent():
    assert issubclass(KMSMasterKeyProviderConfig, MasterKeyProviderConfig)


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_converts(cls, kwargs):
    test = cls(**kwargs)
    assert isinstance(test.key_ids, tuple)
    assert isinstance(test.region_names, tuple)


def test_attributes_defaults():
    test = KMSMasterKeyProviderConfig()
    assert isinstance(test.botocore_session, botocore.session.Session)
    assert test.key_ids == ()
    assert test.region_names == ()
