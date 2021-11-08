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
"""Unit test suite for aws_encryption_sdk.compatability"""
import sys

import mock
import pytest

from aws_encryption_sdk.compatability import _warn_deprecated_python

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestWarnDeprecatedPython:
    def test_happy_version(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = 3
            v_info.minor = 6
            with pytest.warns(None) as record:
                _warn_deprecated_python()
            assert len(record) == 0

    def test_below_warn(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = 2
            v_info.minor = 7
            with pytest.warns(DeprecationWarning):
                _warn_deprecated_python()
