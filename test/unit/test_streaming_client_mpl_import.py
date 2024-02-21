# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Unit test suite to validate aws_encryption_sdk.streaming_client MPL import logic."""

import pytest

import aws_encryption_sdk.streaming_client

pytestmark = [pytest.mark.unit, pytest.mark.local]


# Check if MPL is installed, and skip tests based on its installation status
# Ideally, this logic would be based on mocking imports and testing logic,
# but doing that introduces errors that cause other tests to fail.
try:
    import aws_cryptographic_materialproviders  # noqa pylint: disable=unused-import
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
