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

from aws_encryption_sdk.exceptions import (
    ConfigMismatchError,
    MalformedArnError,
    MasterKeyProviderError,
    UnknownRegionError,
)
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.key_providers.kms import (
    BaseKMSMasterKeyProvider,
    DiscoveryAwsKmsMasterKeyProvider,
    DiscoveryFilter,
    KMSMasterKey,
    StrictAwsKmsMasterKeyProvider,
)

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
    provider = StrictAwsKmsMasterKeyProvider(region_names=region_names, key_ids=key_ids)
    assert provider.master_key("alias/key_1").config.client.meta.region_name == region_names[0]


class KMSMasterKeyProviderTestBase(object):
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


class UnitTestBaseKMSMasterKeyProvider(BaseKMSMasterKeyProvider):
    """Test class to enable direct testing of the shared BaseKMSMasterKeyProvider. Does nothing except
    implement a no-op version of the abstract validate_config method."""

    def validate_config(self):
        pass


class TestBaseKMSMasterKeyProvider(KMSMasterKeyProviderTestBase):
    def test_parent(self):
        assert issubclass(BaseKMSMasterKeyProvider, MasterKeyProvider)

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_clients_from_list")
    def test_init_with_region_names(self, mock_add_clients):
        region_names = (sentinel.region_name_1, sentinel.region_name_2)
        test = UnitTestBaseKMSMasterKeyProvider(region_names=region_names)
        mock_add_clients.assert_called_once_with(region_names)
        assert test.default_region is sentinel.region_name_1

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_client")
    def test_init_with_default_region_found(self, mock_add_regional_client):
        test = UnitTestBaseKMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        assert test.default_region is None
        with patch.object(
            test.config.botocore_session, "get_config_variable", return_value=sentinel.default_region
        ) as mock_get_config:
            test._process_config()
            mock_get_config.assert_called_once_with("region")
            assert test.default_region is sentinel.default_region
            mock_add_regional_client.assert_called_with(sentinel.default_region)

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_client")
    def test_init_with_default_region_not_found(self, mock_add_regional_client):
        test = UnitTestBaseKMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        assert test.default_region is None
        with patch.object(test.config.botocore_session, "get_config_variable", return_value=None) as mock_get_config:
            test._process_config()
            mock_get_config.assert_called_once_with("region")
            assert test.default_region is None
            assert not mock_add_regional_client.called

    def test_add_regional_client_new(self):
        test = UnitTestBaseKMSMasterKeyProvider()
        test._regional_clients = {}
        test.add_regional_client("ex_region_name")
        self.mock_boto3_session.assert_called_with(botocore_session=ANY)
        self.mock_boto3_session_instance.client.assert_called_with(
            "kms",
            region_name="ex_region_name",
            config=test._user_agent_adding_config,
        )
        assert test._regional_clients["ex_region_name"] is self.mock_boto3_client_instance

    def test_add_regional_client_exists(self):
        test = UnitTestBaseKMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        test._regional_clients["ex_region_name"] = sentinel.existing_client
        test.add_regional_client("ex_region_name")
        assert not self.mock_boto3_session.called

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_client")
    def test_add_regional_clients_from_list(self, mock_add_client):
        test = UnitTestBaseKMSMasterKeyProvider()
        test.add_regional_clients_from_list([sentinel.region_a, sentinel.region_b, sentinel.region_c])
        mock_add_client.assert_has_calls((call(sentinel.region_a), call(sentinel.region_b), call(sentinel.region_c)))

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_client")
    def test_client_valid_region_name(self, mock_add_client):
        test = UnitTestBaseKMSMasterKeyProvider()
        test._regional_clients["us-east-1"] = self.mock_boto3_client_instance
        client = test._client("arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")
        mock_add_client.assert_called_with("us-east-1")
        assert client is self.mock_boto3_client_instance

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_client")
    def test_client_no_region_name_with_default(self, mock_add_client):
        test = UnitTestBaseKMSMasterKeyProvider()
        test.default_region = sentinel.default_region
        test._regional_clients[sentinel.default_region] = sentinel.default_client
        client = test._client("")
        assert client is sentinel.default_client
        mock_add_client.assert_called_with(sentinel.default_region)

    def test_client_no_region_name_without_default(self):
        test = UnitTestBaseKMSMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        with pytest.raises(UnknownRegionError) as excinfo:
            test._client("")
        excinfo.match("No default region found and no region determinable from key id: *")

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key(self, mock_client):
        """v1.2.4 : master key equality is left to the Python object identity now"""
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = "example key info asdf"
        test = UnitTestBaseKMSMasterKeyProvider()
        key = test._new_master_key(key_info)
        check_key = KMSMasterKey(key_id=key_info, client=self.mock_boto3_client_instance)
        assert key != check_key

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key_with_discovery_filter_invalid_arn(self, mock_client):
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = "example key info asdf"
        test = UnitTestBaseKMSMasterKeyProvider()
        test.config.discovery_filter = DiscoveryFilter(partition="aws", account_ids=["123"])

        with pytest.raises(MalformedArnError) as excinfo:
            test._new_master_key(key_info)
        excinfo.match("Resource {} could not be parsed as an ARN".format(key_info))
        mock_client.assert_not_called()

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key_with_discovery_filter_account_not_allowed(self, mock_client):
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        test = UnitTestBaseKMSMasterKeyProvider()
        test.config.discovery_filter = DiscoveryFilter(partition="aws", account_ids=["123"])

        with pytest.raises(MasterKeyProviderError) as excinfo:
            test._new_master_key(key_info)
        excinfo.match("Key {} not allowed by this Master Key Provider".format(key_info))
        mock_client.assert_not_called()

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key_with_discovery_filter_partition_not_allowed(self, mock_client):
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        test = UnitTestBaseKMSMasterKeyProvider()
        test.config.discovery_filter = DiscoveryFilter(partition="aws-cn", account_ids=["123"])

        with pytest.raises(MasterKeyProviderError) as excinfo:
            test._new_master_key(key_info)
        excinfo.match("Key {} not allowed by this Master Key Provider".format(key_info))
        mock_client.assert_not_called()

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key_with_discovery_filter_success(self, mock_client):
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = b"arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        test = UnitTestBaseKMSMasterKeyProvider()
        test.config.discovery_filter = DiscoveryFilter(partition="aws", account_ids=["222222222222"])

        key = test._new_master_key(key_info)
        assert key.key_id == key_info
        mock_client.assert_called_with(to_str(key_info))

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key_no_vend(self, mock_client):
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = b"arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        test = UnitTestBaseKMSMasterKeyProvider(key_ids=[key_info])

        key = test._new_master_key(key_info)
        assert key.key_id == key_info


class TestDiscoveryKMSMasterKeyProvider(KMSMasterKeyProviderTestBase):
    def test_parent(self):
        assert issubclass(DiscoveryAwsKmsMasterKeyProvider, BaseKMSMasterKeyProvider)

    def test_init_bare(self):
        test = DiscoveryAwsKmsMasterKeyProvider()
        assert test.vend_masterkey_on_decrypt

    def test_init_failure_discovery_filter_missing_account_ids(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(discovery_filter=DiscoveryFilter(partition="aws"))
        excinfo.match("you must include both account ids and partition")

    def test_init_failure_discovery_filter_empty_account_ids(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(discovery_filter=DiscoveryFilter(account_ids=[], partition="aws"))
        excinfo.match("you must include both account ids and partition")

    def test_init_failure_discovery_filter_empty_account_id_string(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(
                discovery_filter=DiscoveryFilter(account_ids=["123456789012", ""], partition="aws")
            )
        excinfo.match("account ids must be non-empty strings")

    def test_init_failure_discovery_filter_missing_partition(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(discovery_filter=DiscoveryFilter(account_ids=["123"]))
        excinfo.match("you must include both account ids and partition")

    def test_init_failure_discovery_filter_empty_partition(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(discovery_filter=DiscoveryFilter(account_ids=["123"], partition=""))
        excinfo.match("you must include both account ids and partition")

    def test_init_failure_with_key_ids(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(
                discovery_filter=DiscoveryFilter(account_ids=["123"], partition="aws"), key_ids=["1234"]
            )
        excinfo.match("To explicitly identify which keys should be used, use a StrictAwsKmsMasterKeyProvider.")

    def test_init_success(self):
        discovery_filter = DiscoveryFilter(account_ids=["1234"], partition="aws")
        test = DiscoveryAwsKmsMasterKeyProvider(discovery_filter=discovery_filter)

        assert test.vend_masterkey_on_decrypt
        assert test.config.discovery_filter == discovery_filter


class TestStrictKMSMasterKeyProvider(KMSMasterKeyProviderTestBase):
    def test_parent(self):
        assert issubclass(StrictAwsKmsMasterKeyProvider, BaseKMSMasterKeyProvider)

    def test_init_bare_fails(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider()
        excinfo.match("To enable strict mode you must provide key ids")

    def test_init_empty_key_ids_fails(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=[])
        excinfo.match("To enable strict mode you must provide key ids")

    def test_init_null_key_id_fails(self):
        key_ids = ("arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", None)
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        excinfo.match("Key ids must be valid AWS KMS ARNs")

    def test_init_empty_string_key_id_fails(self):
        key_ids = ("arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", "")
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        excinfo.match("Key ids must be valid AWS KMS ARNs")

    @patch("aws_encryption_sdk.key_providers.kms.StrictAwsKmsMasterKeyProvider.add_master_keys_from_list")
    def test_init_with_discovery_fails(self, mock_add_keys):
        key_ids = (
            "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:us-east-1:333333333333:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        )
        discovery_filter = DiscoveryFilter(account_ids=["1234"], partition="aws")
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=key_ids, discovery_filter=discovery_filter)
        excinfo.match("To enable discovery mode, use a DiscoveryAwsKmsMasterKeyProvider")
        mock_add_keys.assert_not_called()

    @patch("aws_encryption_sdk.key_providers.kms.StrictAwsKmsMasterKeyProvider.add_master_keys_from_list")
    def test_init_with_key_ids(self, mock_add_keys):
        key_ids = (
            "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:us-east-1:333333333333:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        )
        test = StrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        assert not test.vend_masterkey_on_decrypt
        mock_add_keys.assert_called_once_with(key_ids)
