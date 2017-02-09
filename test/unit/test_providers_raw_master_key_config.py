"""Unit test suite to validate aws_encryption_sdk.key_providers.raw.RawMasterKeyConfig"""
import unittest

import attr
import six

from aws_encryption_sdk.internal.crypto import WrappingKey
import aws_encryption_sdk.internal.str_ops
from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyConfig


class TestRawMasterKeyConfig(unittest.TestCase):

    def test_parent(self):
        assert issubclass(RawMasterKeyConfig, MasterKeyConfig)

    def test_provider_id(self):
        assert isinstance(RawMasterKeyConfig.provider_id, attr.Attribute)
        assert RawMasterKeyConfig.provider_id.default is attr.NOTHING
        assert RawMasterKeyConfig.provider_id.validator.type == (six.string_types, bytes)
        assert RawMasterKeyConfig.provider_id.convert is aws_encryption_sdk.internal.str_ops.to_str

    def test_wrapping_key(self):
        assert isinstance(RawMasterKeyConfig.wrapping_key, attr.Attribute)
        assert RawMasterKeyConfig.wrapping_key.default is attr.NOTHING
        assert RawMasterKeyConfig.wrapping_key.validator.type is WrappingKey
