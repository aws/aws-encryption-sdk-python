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
"""Unit test suite for ensuring the Python Runtime is supported."""
import datetime
import sys

import mock
import pytest

from aws_encryption_sdk import check_python_version
from aws_encryption_sdk.identifiers import PythonVersionSupport

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestBeforeErrorDate:
    def test_happy_version(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = PythonVersionSupport.WARN_BELOW_MAJOR
            v_info.minor = PythonVersionSupport.WARN_BELOW_MINOR
            with pytest.warns(None) as record:
                check_python_version(error_date=datetime.datetime.now() + datetime.timedelta(days=1))
            assert len(record) == 0

    def test_below_warn(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = PythonVersionSupport.WARN_BELOW_MAJOR - 1
            v_info.minor = PythonVersionSupport.WARN_BELOW_MINOR
            with pytest.warns(DeprecationWarning):
                check_python_version(error_date=datetime.datetime.now() + datetime.timedelta(days=1))


class TestAfterErrorDate:
    def test_happy_version(self, capsys):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = PythonVersionSupport.WARN_BELOW_MAJOR
            v_info.minor = PythonVersionSupport.WARN_BELOW_MINOR
            with pytest.warns(None) as record:
                check_python_version(error_date=datetime.datetime.now() - datetime.timedelta(days=1))
            assert len(record) == 0
            captured = capsys.readouterr().err
            assert "ERROR" not in captured

    def test_below_error(self, capsys):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = PythonVersionSupport.ERROR_BELOW_MAJOR
            v_info.minor = PythonVersionSupport.ERROR_BELOW_MINOR - 1
            with pytest.warns(None) as record:
                check_python_version(error_date=datetime.datetime.now() - datetime.timedelta(days=1))
            assert len(record) == 0
            captured = capsys.readouterr().err
            assert "ERROR" in captured
