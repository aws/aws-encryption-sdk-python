# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the basic data key caching example in the AWS-hosted documentation."""
import pytest

from ...src.legacy.data_key_caching_basic import encrypt_with_caching
from .examples_test_utils import get_cmk_arn

pytestmark = [pytest.mark.examples]


def test_encrypt_with_caching():
    cmk_arn = get_cmk_arn()
    encrypt_with_caching(kms_cmk_arn=cmk_arn, max_age_in_cache=10.0, cache_capacity=10)
