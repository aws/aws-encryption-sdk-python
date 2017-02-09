"""Unit test suite to validate aws_encryption_sdk.key_providers.kms.KMSMasterKeyConfig"""
import unittest

import attr
import botocore.client

from aws_encryption_sdk.key_providers.base import MasterKeyConfig
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyConfig, _PROVIDER_ID


class TestKMSMasterKeyConfig(unittest.TestCase):

    def test_parent(self):
        assert issubclass(KMSMasterKeyConfig, MasterKeyConfig)

    def test_provider_id(self):
        assert KMSMasterKeyConfig.provider_id is _PROVIDER_ID

    def test_client(self):
        assert isinstance(KMSMasterKeyConfig.client, attr.Attribute)
        assert KMSMasterKeyConfig.client.default is attr.NOTHING
        assert KMSMasterKeyConfig.client.validator.type is botocore.client.BaseClient

    def test_grant_tokens(self):
        assert isinstance(KMSMasterKeyConfig.grant_tokens, attr.Attribute)
        assert isinstance(KMSMasterKeyConfig.grant_tokens.default, attr.Factory)
        assert KMSMasterKeyConfig.grant_tokens.default.factory is list
