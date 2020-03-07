# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for ``aws_encryption_sdk.keyrings.aws_kms.client_cache``."""
import pytest
from botocore.config import Config
from botocore.exceptions import BotoCoreError
from botocore.session import Session

from aws_encryption_sdk.keyrings.aws_kms.client_cache import ClientCache

pytestmark = [pytest.mark.integ]


def test_client_cache_removes_bad_client():
    cache = ClientCache(botocore_session=Session(), client_config=Config())
    fake_region = "us-fake-1"

    initial_client = cache.client(fake_region, "kms")

    assert fake_region in cache._cache

    with pytest.raises(BotoCoreError):
        initial_client.encrypt(KeyId="foo", Plaintext=b"bar")

    assert fake_region not in cache._cache


def test_regional_client_does_not_modify_botocore_session():
    cache = ClientCache(botocore_session=Session(), client_config=Config())
    fake_region = "us-fake-1"

    assert cache._botocore_session.get_config_variable("region") != fake_region
    cache.client(fake_region, "kms")
    assert cache._botocore_session.get_config_variable("region") != fake_region


def test_client_cache_remove_bad_client_when_already_removed():
    cache = ClientCache(botocore_session=Session(), client_config=Config())
    fake_region = "us-fake-1"

    initial_client = cache.client(fake_region, "kms")

    assert fake_region in cache._cache
    del cache._cache[fake_region]

    with pytest.raises(BotoCoreError):
        initial_client.encrypt(KeyId="foo", Plaintext=b"bar")

    assert fake_region not in cache._cache
