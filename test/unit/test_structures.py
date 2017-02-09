"""Unit test suite for aws_encryption_sdk.structures"""
import unittest

import six

import aws_encryption_sdk.structures


class TestStructures(unittest.TestCase):

    def master_key_info_str_key_info(self):
        test = aws_encryption_sdk.structures.MasterKeyInfo(
            provider_id=None,
            key_info=six.u('asdf')
        )
        assert test.key_info == six.b('asdf')

    def master_key_info_bytes_key_info(self):
        test = aws_encryption_sdk.structures.MasterKeyInfo(
            provider_id=None,
            key_info=six.b('asdf')
        )
        assert test.key_info == six.b('asdf')
