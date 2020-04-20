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
"""Unit test suite to validate aws_encryption_sdk.key_providers.base.MasterKeyProviderConfig"""
import pytest

from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.unit, pytest.mark.local]

# Nothing to test at this time, but import will ensure that it exists.
# If this MasterKeyProviderConfig has attributes added in the future, they should be tested here.
