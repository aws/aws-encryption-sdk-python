# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite to validate aws_encryption_sdk.streaming_client MPL import logic."""

import pytest

import aws_encryption_sdk.streaming_client

pytestmark = [pytest.mark.unit, pytest.mark.local]


# Check if MPL is installed, and skip tests based on its installation status
# Ideally, this logic would be based on mocking imports and testing logic,
# but doing that introduces errors that cause other tests to fail.
try:
    import aws_cryptographic_material_providers  # noqa pylint: disable=unused-import
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


@pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
def test_GIVEN_test_has_mpl_is_True_THEN_streaming_client_has_mpl_is_True():
    """If the MPL IS installed in the runtime environment,
    assert the streaming client has _HAS_MPL set to True"""

    assert hasattr(aws_encryption_sdk.streaming_client, "_HAS_MPL")
    assert aws_encryption_sdk.streaming_client._HAS_MPL is True


@pytest.mark.skipif(HAS_MPL, reason="Test should only be executed without MPL in installation")
def test_GIVEN_test_has_mpl_is_False_THEN_streaming_client_has_mpl_is_False():
    """If the MPL IS NOT installed in the runtime environment,
    assert the streaming client has _HAS_MPL set to False"""

    assert hasattr(aws_encryption_sdk.streaming_client, "_HAS_MPL")
    assert aws_encryption_sdk.streaming_client._HAS_MPL is False
