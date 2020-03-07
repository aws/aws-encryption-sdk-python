# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for ``aws_encryption_sdk.keyrings.aws_kms.client_cache``."""
import pytest
from botocore.config import Config
from botocore.session import Session

from aws_encryption_sdk.keyrings.aws_kms.client_cache import ClientCache

pytestmark = [pytest.mark.functional, pytest.mark.local]


def test_client_cache_caches_clients():
    cache = ClientCache(botocore_session=Session(), client_config=Config())

    initial_client = cache.client("us-west-2", "kms")

    test = cache.client("us-west-2", "kms")

    assert "us-west-2" in cache._cache
    assert test is initial_client


def test_client_cache_new_client():
    cache = ClientCache(botocore_session=Session(), client_config=Config())

    initial_client = cache.client("us-west-2", "kms")

    cache._cache.pop("us-west-2")

    test = cache.client("us-west-2", "kms")

    assert test is not initial_client
