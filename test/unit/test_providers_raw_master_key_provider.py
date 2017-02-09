"""Test suite for aws_encryption_sdk.key_providers.raw.RawMasterKeyProvider"""
import unittest

import attr
from mock import MagicMock, sentinel, patch
import six

from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig, MasterKeyProvider
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from .test_values import VALUES


_MOCK_RAW_MASTER_KEY = MagicMock()


@attr.s
class MockRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    mock_wrapping_key = attr.ib()


class MockRawMasterKeyProvider(RawMasterKeyProvider):
    _config_class = MockRawMasterKeyProviderConfig
    provider_id = VALUES['provider_id']

    def _get_raw_key(self, key_info):
        return self.config.mock_wrapping_key


class TestRawMasterKeyProvider(unittest.TestCase):

    def test_parent(self):
        assert issubclass(RawMasterKeyProvider, MasterKeyProvider)

    def test_get_raw_key_enforcement(self):
        class TestProvider(RawMasterKeyProvider):
            pass
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestProvider *"
        ):
            TestProvider()

    @patch(
        'aws_encryption_sdk.key_providers.raw.RawMasterKeyConfig',
        return_value=sentinel.raw_master_key_config_instance
    )
    def test_new_master_key(self, mock_raw_master_key_config):
        mock_raw_master_key = MagicMock(return_value=sentinel.raw_master_key)
        mock_get_raw_key = MagicMock(return_value=sentinel.wrapping_key)

        class MockRawMasterKeyProvider2(MockRawMasterKeyProvider):
            _master_key_class = mock_raw_master_key
            _get_raw_key = mock_get_raw_key

        mock_master_key_provider = MockRawMasterKeyProvider2(mock_wrapping_key=sentinel.parent_wrapping_key)
        test = mock_master_key_provider._new_master_key(sentinel.key_info)
        mock_raw_master_key_config.assert_called_once_with(
            key_id=sentinel.key_info,
            provider_id=VALUES['provider_id'],
            wrapping_key=sentinel.wrapping_key
        )
        mock_raw_master_key.assert_called_once_with(config=sentinel.raw_master_key_config_instance)
        assert test is sentinel.raw_master_key
