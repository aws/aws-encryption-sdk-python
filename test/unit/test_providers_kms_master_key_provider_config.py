"""Unit test suite to validate aws_encryption_sdk.internal.crypto.providers.kms.KMSMasterKeyProviderConfig"""
import unittest
import attr
import botocore.session
from aws_encryption_sdk.internal.crypto.providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.internal.crypto.providers.kms import KMSMasterKeyProviderConfig


class TestKMSMasterKeyProviderConfig(unittest.TestCase):

    def test_parent(self):
        assert issubclass(KMSMasterKeyProviderConfig, MasterKeyProviderConfig)

    def test_botocore_session(self):
        assert isinstance(KMSMasterKeyProviderConfig.botocore_session, attr.Attribute)
        assert isinstance(KMSMasterKeyProviderConfig.botocore_session.default, attr.Factory)
        assert KMSMasterKeyProviderConfig.botocore_session.default.factory is botocore.session.Session
        assert KMSMasterKeyProviderConfig.botocore_session.validator.type is botocore.session.Session

    def test_key_ids(self):
        assert isinstance(KMSMasterKeyProviderConfig.key_ids, attr.Attribute)
        assert isinstance(KMSMasterKeyProviderConfig.key_ids.default, attr.Factory)
        assert KMSMasterKeyProviderConfig.key_ids.default.factory is list

    def test_region_names(self):
        assert isinstance(KMSMasterKeyProviderConfig.region_names, attr.Attribute)
        assert isinstance(KMSMasterKeyProviderConfig.region_names.default, attr.Factory)
        assert KMSMasterKeyProviderConfig.region_names.default.factory is list
