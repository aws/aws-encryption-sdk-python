# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Unit test suite from aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider"""
import botocore.client
import botocore.session
import pytest
from mock import ANY, MagicMock, call, patch, sentinel

from aws_encryption_sdk.exceptions import UnknownRegionError
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture(autouse=True, params=[True, False], ids=["default region", "no default region"])
def patch_default_region(request, monkeypatch):
    """Run all tests in this module both with a default region set and no default region set.

    This ensures that we do not regress on default region handling.
    https://github.com/aws/aws-encryption-sdk-python/issues/31
    """
    if request.param:
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    else:
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)


def test_init_with_regionless_key_ids_and_region_names():
    key_ids = ("alias/key_1",)
    region_names = ("test-region-1",)
    provider = KMSMasterKeyProvider(region_names=region_names, key_ids=key_ids)
    assert provider.master_key("alias/key_1").config.client.meta.region_name == region_names[0]


class TestKMSMasterKeyProvider(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        self.botocore_no_region_session = botocore.session.Session(session_vars={"region": (None, None, None, None)})
        self.mock_botocore_session_patcher = patch("aws_encryption_sdk.key_providers.kms.botocore.session.Session")
        self.mock_botocore_session = self.mock_botocore_session_patcher.start()
        self.mock_boto3_session_patcher = patch("aws_encryption_sdk.key_providers.kms.boto3.session.Session")
        self.mock_boto3_session = self.mock_boto3_session_patcher.start()
        self.mock_boto3_session_instance = MagicMock()
        self.mock_boto3_session.return_value = self.mock_boto3_session_instance
        self.mock_boto3_client_instance = MagicMock()
        self.mock_boto3_client_instance.__class__ = botocore.client.BaseClient
        self.mock_boto3_session_instance.client.return_value = self.mock_boto3_client_instance
        yield
        # Run tearDown
        self.mock_botocore_session_patcher.stop()
        self.mock_boto3_session_patcher.stop()

    def test_parent(self):
        assert issubclass(KMSMasterKeyProvider, MasterKeyProvider)

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider._process_config")
    def test_init_bare(self, mock_process_config):
        KMSMasterKeyProvider()
        mock_process_config.assert_called_once_with()

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_master_keys_from_list")
    def test_init_with_key_ids(self, mock_add_keys):
        mock_ids = (sentinel.id_1, sentinel.id_2)
        KMSMasterKeyProvider(key_ids=mock_ids)
        mock_add_keys.assert_called_once_with(mock_ids)

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_regional_clients_from_list")
    def test_init_with_region_names(self, mock_add_clients):
        region_names = (sentinel.region_name_1, sentinel.region_name_2)
        test = KMSMasterKeyProvider(region_names=region_names)
        mock_add_clients.assert_called_once_with(region_names)
        assert test.default_region is sentinel.region_name_1

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_regional_client")
    def test_init_with_default_region_found(self, mock_add_regional_client):
        test = KMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        assert test.default_region is None
        with patch.object(
            test.config.botocore_session, "get_config_variable", return_value=sentinel.default_region
        ) as mock_get_config:
            test._process_config()
            mock_get_config.assert_called_once_with("region")
            assert test.default_region is sentinel.default_region
            mock_add_regional_client.assert_called_with(sentinel.default_region)

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_regional_client")
    def test_init_with_default_region_not_found(self, mock_add_regional_client):
        test = KMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        assert test.default_region is None
        with patch.object(test.config.botocore_session, "get_config_variable", return_value=None) as mock_get_config:
            test._process_config()
            mock_get_config.assert_called_once_with("region")
            assert test.default_region is None
            assert not mock_add_regional_client.called

    def test_add_regional_client_new(self):
        test = KMSMasterKeyProvider()
        test._regional_clients = {}
        test.add_regional_client("ex_region_name")
        self.mock_boto3_session.assert_called_with(botocore_session=ANY)
        self.mock_boto3_session_instance.client.assert_called_with(
            "kms", region_name="ex_region_name", config=test._user_agent_adding_config
        )
        assert test._regional_clients["ex_region_name"] is self.mock_boto3_client_instance

    def test_add_regional_client_exists(self):
        test = KMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        test._regional_clients["ex_region_name"] = sentinel.existing_client
        test.add_regional_client("ex_region_name")
        assert not self.mock_boto3_session.called

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_regional_client")
    def test_add_regional_clients_from_list(self, mock_add_client):
        test = KMSMasterKeyProvider()
        test.add_regional_clients_from_list([sentinel.region_a, sentinel.region_b, sentinel.region_c])
        mock_add_client.assert_has_calls((call(sentinel.region_a), call(sentinel.region_b), call(sentinel.region_c)))

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_regional_client")
    def test_client_valid_region_name(self, mock_add_client):
        test = KMSMasterKeyProvider()
        test._regional_clients["us-east-1"] = self.mock_boto3_client_instance
        client = test._client("arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")
        mock_add_client.assert_called_with("us-east-1")
        assert client is self.mock_boto3_client_instance

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider.add_regional_client")
    def test_client_no_region_name_with_default(self, mock_add_client):
        test = KMSMasterKeyProvider()
        test.default_region = sentinel.default_region
        test._regional_clients[sentinel.default_region] = sentinel.default_client
        client = test._client("")
        assert client is sentinel.default_client
        mock_add_client.assert_called_with(sentinel.default_region)

    def test_client_no_region_name_without_default(self):
        test = KMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        with pytest.raises(UnknownRegionError) as excinfo:
            test._client("")
        excinfo.match("No default region found and no region determinable from key id: *")

    @patch("aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider._client")
    def test_new_master_key(self, mock_client):
        """v1.2.4 : master key equality is left to the Python object identity now"""
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = "example key info asdf"
        test = KMSMasterKeyProvider()
        key = test._new_master_key(key_info)
        check_key = KMSMasterKey(key_id=key_info, client=self.mock_boto3_client_instance)
        assert key != check_key
