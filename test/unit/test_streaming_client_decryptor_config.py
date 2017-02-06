"""Unit test suite to validate aws_encryption_sdk.streaming_client.DecryptorConfig"""
import unittest
from aws_encryption_sdk.streaming_client import DecryptorConfig, _ClientConfig


class TestDecryptorConfig(unittest.TestCase):

    def test_parent(self):
        assert issubclass(DecryptorConfig, _ClientConfig)
