# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.compatability"""
import sys
import warnings

import mock
import pytest

from aws_encryption_sdk.compatability import _warn_deprecated_python

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestWarnDeprecatedPython:
    def test_happy_version(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = 3
            v_info.minor = 6
            with warnings.catch_warnings(record=True) as record:
                warnings.simplefilter("always")
                _warn_deprecated_python()
            assert len(record) == 0

    def test_below_warn(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = 2
            v_info.minor = 7
            with pytest.warns(DeprecationWarning):
                _warn_deprecated_python()
