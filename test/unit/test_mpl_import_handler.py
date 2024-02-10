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
"""Test suite to verify the mpl_import_handler module handles importing the MPL correctly."""
import pytest
from mock import patch

from aws_encryption_sdk.mpl import mpl_import_handler

pytestmark = [pytest.mark.unit, pytest.mark.local]

@patch("aws_encryption_sdk.mpl.mpl_import_handler._import_mpl")
def test_GIVEN_import_mpl_succeeds_WHEN_call_has_mpl_THEN_return_True(import_mock):
    # Mock a successful import of `aws_cryptographic_material_providers`
    import_mock.return_value = None  # No exception means successful import

    assert mpl_import_handler.has_mpl() is True

@patch("aws_encryption_sdk.mpl.mpl_import_handler._import_mpl")
def test_GIVEN_import_mpl_fails_WHEN_call_has_mpl_THEN_return_False(import_mock):
    # Mock not having a `aws_cryptographic_material_providers` module,
    # even if it is installed in the Python environment
    import_mock.side_effect = ImportError()

    assert not mpl_import_handler.has_mpl()