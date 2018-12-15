# -*- coding: utf-8 -*-
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
"""Test suite for aws_encryption_sdk.internal.str_ops"""
import codecs

import pytest

import aws_encryption_sdk.internal.str_ops

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestStrOps(object):
    def test_to_str_str2str(self):
        test = aws_encryption_sdk.internal.str_ops.to_str("asdf")
        assert test == "asdf"

    def test_to_str_bytes2str(self):
        test = aws_encryption_sdk.internal.str_ops.to_str(b"asdf")
        assert test == "asdf"

    def test_to_bytes_str2bytes(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes("asdf")
        assert test == b"asdf"

    def test_to_bytes_bytes2bytes(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes(b"\x3a\x00\x99")
        assert test == b"\x3a\x00\x99"

    def test_to_str_bytes2unicode(self):
        test = aws_encryption_sdk.internal.str_ops.to_str(codecs.encode(u"Предисловие", "utf-8"))
        assert test == u"Предисловие"

    def test_to_str_unicode2unicode(self):
        test = aws_encryption_sdk.internal.str_ops.to_str(u"Предисловие")
        assert test == u"Предисловие"

    def test_to_str_unicode2bytes(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes(u"Предисловие")
        assert test == codecs.encode(u"Предисловие", "utf-8")

    def test_to_bytes_utf82utf8(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes(codecs.encode(u"Предисловие", "utf-8"))
        assert test == codecs.encode(u"Предисловие", "utf-8")
