"""Unit test suite to validate aws_encryption_sdk.streaming_client._ClientConfig"""
import unittest
import attr
import aws_encryption_sdk.internal.utils
from aws_encryption_sdk.internal.crypto.providers.base import MasterKeyProvider
from aws_encryption_sdk.streaming_client import _ClientConfig


class TestClientConfig(unittest.TestCase):

    def test_source(self):
        assert isinstance(_ClientConfig.source, attr.Attribute)
        assert _ClientConfig.source.default is attr.NOTHING
        assert _ClientConfig.source.convert is aws_encryption_sdk.internal.utils.prep_stream_data

    def test_key_provider(self):
        assert isinstance(_ClientConfig.key_provider, attr.Attribute)
        assert _ClientConfig.key_provider.default is attr.NOTHING
        assert _ClientConfig.key_provider.validator.type is MasterKeyProvider

    def test_source_length(self):
        assert isinstance(_ClientConfig.source_length, attr.Attribute)
        assert _ClientConfig.source_length.default is None
        assert _ClientConfig.source_length.validator.validator.type is int

    def test_line_length(self):
        assert isinstance(_ClientConfig.line_length, attr.Attribute)
        assert _ClientConfig.line_length.default is aws_encryption_sdk.internal.defaults.LINE_LENGTH
        assert _ClientConfig.line_length.validator.type is int
