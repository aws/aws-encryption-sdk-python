# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite to verify calculated values in aws_encryption_sdk.internal.defaults"""
import pytest

import aws_encryption_sdk.internal.defaults

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestDefaults(object):
    def test_max_frame_count(self):
        max_frame_count = pow(2, 32) - 1
        assert aws_encryption_sdk.internal.defaults.MAX_FRAME_COUNT == max_frame_count

    def test_max_frame_size(self):
        max_frame_size = pow(2, 31) - 1
        assert aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE == max_frame_size

    def test_max_non_framed_size(self):
        max_non_framed_size = pow(2, 36) - 32
        assert aws_encryption_sdk.internal.defaults.MAX_NON_FRAMED_SIZE == max_non_framed_size

    def test_max_byte_array_size(self):
        max_byte_array_size = pow(2, 16) - 1
        assert aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE == max_byte_array_size
