"""Unit test suite to validate aws_encryption_sdk.streaming_client.EncryptorConfig"""
import unittest

import attr

import aws_encryption_sdk.internal.defaults
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.streaming_client import EncryptorConfig, _ClientConfig


class TestEncryptorConfig(unittest.TestCase):

    def test_parent(self):
        assert issubclass(EncryptorConfig, _ClientConfig)

    def test_encryption_context(self):
        assert isinstance(EncryptorConfig.encryption_context, attr.Attribute)
        assert isinstance(EncryptorConfig.encryption_context.default, attr.Factory)
        assert EncryptorConfig.encryption_context.default.factory is dict
        assert EncryptorConfig.encryption_context.validator.type is dict

    def test_algorithm(self):
        assert isinstance(EncryptorConfig.algorithm, attr.Attribute)
        assert EncryptorConfig.algorithm.default is aws_encryption_sdk.internal.defaults.ALGORITHM
        assert EncryptorConfig.algorithm.validator.type is Algorithm

    def test_frame_length(self):
        assert isinstance(EncryptorConfig.frame_length, attr.Attribute)
        assert EncryptorConfig.frame_length.default is aws_encryption_sdk.internal.defaults.FRAME_LENGTH
        assert EncryptorConfig.frame_length.validator.type is int
