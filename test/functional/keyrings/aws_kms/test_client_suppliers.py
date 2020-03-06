# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for ``aws_encryption_sdk.keyrings.aws_kms.client_suppliers``."""
import pytest
from botocore.session import Session

from aws_encryption_sdk.exceptions import UnknownRegionError
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import (
    AllowRegionsClientSupplier,
    ClientSupplier,
    DefaultClientSupplier,
    DenyRegionsClientSupplier,
)

pytestmark = [pytest.mark.functional, pytest.mark.local]


def test_default_supplier_not_implemented():
    test = ClientSupplier()

    with pytest.raises(NotImplementedError) as excinfo:
        test("region")

    excinfo.match("'ClientSupplier' does not implement 'client'")


def test_default_supplier_uses_cache():
    supplier = DefaultClientSupplier()

    region = "us-west-2"
    expected = supplier._cache.client(region_name=region, service="kms")

    test = supplier(region)

    assert test is expected


def test_default_supplier_passes_session():
    botocore_session = Session()

    test = DefaultClientSupplier(botocore_session=botocore_session)

    assert test._cache._botocore_session is botocore_session


def test_allow_regions_supplier_passes_session():
    botocore_session = Session()

    test = AllowRegionsClientSupplier(allowed_regions=["us-west-2"], botocore_session=botocore_session)

    assert test._supplier._botocore_session is botocore_session


@pytest.mark.parametrize(
    "kwargs",
    (
        pytest.param(dict(allowed_regions="foo"), id="allowed_regions is a string"),
        pytest.param(dict(allowed_regions=["foo", 5]), id="allowed_regions contains invalid type"),
    ),
)
def test_allow_regions_supplier_invalid_parameters(kwargs):
    with pytest.raises(TypeError):
        AllowRegionsClientSupplier(**kwargs)


def test_allow_regions_supplier_allows_allowed_region():
    test = AllowRegionsClientSupplier(allowed_regions=["us-west-2", "us-east-2"])

    assert test("us-west-2")


def test_allow_regions_supplier_denied_not_allowed_region():
    test = AllowRegionsClientSupplier(allowed_regions=["us-west-2", "us-east-2"])

    with pytest.raises(UnknownRegionError) as excinfo:
        test("ap-northeast-2")

    excinfo.match("Unable to provide client for region 'ap-northeast-2'")


def test_deny_regions_supplier_passes_session():
    botocore_session = Session()

    test = DenyRegionsClientSupplier(denied_regions=["us-west-2"], botocore_session=botocore_session)

    assert test._supplier._botocore_session is botocore_session


@pytest.mark.parametrize(
    "kwargs",
    (
        pytest.param(dict(denied_regions="foo"), id="denied_regions is a string"),
        pytest.param(dict(denied_regions=["foo", 5]), id="denied_regions contains invalid type"),
    ),
)
def test_deny_regions_supplier_invalid_parameters(kwargs):
    with pytest.raises(TypeError):
        DenyRegionsClientSupplier(**kwargs)


def test_deny_regions_supplier_denies_denied_region():
    test = DenyRegionsClientSupplier(denied_regions=["us-west-2", "us-east-2"])

    with pytest.raises(UnknownRegionError) as excinfo:
        test("us-west-2")

    excinfo.match("Unable to provide client for region 'us-west-2'")


def test_deny_regions_supplier_allows_not_denied_region():
    test = DenyRegionsClientSupplier(denied_regions=["us-west-2", "us-east-2"])

    assert test("ap-northeast-2")
