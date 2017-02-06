"""Unit test suite to validate aws_encryption_sdk.internal.crypto.providers.base.MasterKeyConfig"""
import unittest
import attr
import six
import aws_encryption_sdk.internal.str_ops
from aws_encryption_sdk.internal.crypto.providers.base import MasterKeyConfig


class TestMasterKeyProviderConfig(unittest.TestCase):

    def test_key_id(self):
        assert isinstance(MasterKeyConfig.key_id, attr.Attribute)
        assert MasterKeyConfig.key_id.default is attr.NOTHING
        assert MasterKeyConfig.key_id.validator.type == (six.string_types, bytes)
        assert MasterKeyConfig.key_id.convert is aws_encryption_sdk.internal.str_ops.to_bytes

    def test_provider_id_enforcement(self):
        class TestConfig(MasterKeyConfig):
            pass

        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestConfig *"
        ):
            TestConfig()
