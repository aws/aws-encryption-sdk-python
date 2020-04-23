# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for ``aws_encryption_sdk.keyrings.aws_kms.client_suppliers``."""
import pytest
from botocore.client import BaseClient
from botocore.config import Config
from botocore.session import Session

from aws_encryption_sdk.exceptions import UnknownRegionError
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import (
    AllowRegionsClientSupplier,
    ClientSupplier,
    DefaultClientSupplier,
    DenyRegionsClientSupplier,
)

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.functional, pytest.mark.local]


class AlwaysOneRegionClientSupplier(ClientSupplier):
    """Client supplier that always returns a client for a specific region."""

    def __init__(self, region_name):
        # type: (str) -> None
        self._region_name = region_name
        self._inner_supplier = DefaultClientSupplier()

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        return self._inner_supplier(self._region_name)


def test_default_supplier_not_implemented():
    test = ClientSupplier()

    with pytest.raises(NotImplementedError) as excinfo:
        test("region")

    excinfo.match("'ClientSupplier' is not callable")


def test_default_supplier_uses_cache():
    supplier = DefaultClientSupplier()

    region = "us-west-2"
    expected = supplier._client_cache.client(region_name=region, service="kms")

    test = supplier(region)

    assert test is expected


def test_default_supplier_passes_through_configs():
    session = Session()
    config = Config()

    test = DefaultClientSupplier(botocore_session=session, client_config=config)

    assert test._client_cache._botocore_session is session
    assert test._client_cache._client_config is config


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


def test_allow_deny_nested_supplier():
    test_allow = AllowRegionsClientSupplier(
        allowed_regions=["us-west-2", "us-east-2"], client_supplier=DefaultClientSupplier()
    )
    test_deny = DenyRegionsClientSupplier(denied_regions=["us-west-2"], client_supplier=test_allow)

    # test_allow allows us-west-2
    test_allow("us-west-2")

    # test_deny denies us-west-2 even though its internal supplier (test_allow) allows it
    with pytest.raises(UnknownRegionError) as excinfo:
        test_deny("us-west-2")

    excinfo.match("Unable to provide client for region 'us-west-2'")


def test_deny_region_block_on_response():
    region = "us-west-2"
    test = DenyRegionsClientSupplier(
        denied_regions=[region], client_supplier=AlwaysOneRegionClientSupplier(region_name=region)
    )

    # Catch the blocked region on response.
    with pytest.raises(UnknownRegionError):
        test(None)


def test_allow_region_block_on_response():
    test = AllowRegionsClientSupplier(
        allowed_regions=[None, "us-west-2"], client_supplier=AlwaysOneRegionClientSupplier(region_name="us-east-2")
    )

    # Catch the blocked region on response.
    with pytest.raises(UnknownRegionError):
        test(None)
