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

import sys
from importlib import reload

import pytest
from mock import Mock, patch

import aws_encryption_sdk.streaming_client

pytestmark = [pytest.mark.unit, pytest.mark.local]


@patch.object(aws_encryption_sdk.streaming_client.mpl_import_handler, "has_mpl")
def test_GIVEN_has_mpl_returns_True_WHEN_import_streaming_client_THEN_imports_mpl_modules(has_mpl_mock):
    has_mpl_mock.return_value = True

    # Mock any imports used in the try/catch block
    # If more imports are added there, then this needs to be expanded
    # This unit test should pass even if the MPL is not installed
    sys.modules['aws_cryptographic_materialproviders.mpl.client'] = Mock()
    sys.modules['aws_cryptographic_materialproviders.mpl.config'] = Mock()
    sys.modules['aws_cryptographic_materialproviders.mpl.models'] = Mock()
    sys.modules['aws_cryptographic_materialproviders.mpl.references'] = Mock()

    # Reload module given the mock
    reload(aws_encryption_sdk.streaming_client)

    assert hasattr(aws_encryption_sdk.streaming_client, "_HAS_MPL")
    assert aws_encryption_sdk.streaming_client._HAS_MPL is True


@patch.object(aws_encryption_sdk.streaming_client.mpl_import_handler, "has_mpl")
def test_GIVEN_has_mpl_returns_False_WHEN_import_streaming_client_THEN_does_not_import_mpl_modules(has_mpl_mock):
    has_mpl_mock.return_value = False

    # Reload module given the mock
    reload(aws_encryption_sdk.streaming_client)

    assert hasattr(aws_encryption_sdk.streaming_client, "_HAS_MPL")
    assert aws_encryption_sdk.streaming_client._HAS_MPL is False
