# -*- coding: utf-8 -*-
"""Test suite for aws_encryption_sdk.internal.str_ops"""
import codecs
import unittest
import aws_encryption_sdk.internal.str_ops


class TestStrOps(unittest.TestCase):

    def test_to_str_str2str(self):
        test = aws_encryption_sdk.internal.str_ops.to_str('asdf')
        assert test == 'asdf'

    def test_to_str_bytes2str(self):
        test = aws_encryption_sdk.internal.str_ops.to_str(b'asdf')
        assert test == 'asdf'

    def test_to_bytes_str2bytes(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes('asdf')
        assert test == b'asdf'

    def test_to_bytes_bytes2bytes(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes(b'\x3a\x00\x99')
        assert test == b'\x3a\x00\x99'

    def test_to_str_bytes2unicode(self):
        test = aws_encryption_sdk.internal.str_ops.to_str(codecs.encode(u'Предисловие', 'utf-8'))
        assert test == u'Предисловие'

    def test_to_str_unicode2unicode(self):
        test = aws_encryption_sdk.internal.str_ops.to_str(u'Предисловие')
        assert test == u'Предисловие'

    def test_to_str_unicode2bytes(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes(u'Предисловие')
        assert test == codecs.encode(u'Предисловие', 'utf-8')

    def test_to_bytes_utf82utf8(self):
        test = aws_encryption_sdk.internal.str_ops.to_bytes(codecs.encode(u'Предисловие', 'utf-8'))
        assert test == codecs.encode(u'Предисловие', 'utf-8')
