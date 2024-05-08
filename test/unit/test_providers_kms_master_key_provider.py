# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
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
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.key_providers.kms import (
    BaseKMSMasterKeyProvider,
    DiscoveryAwsKmsMasterKeyProvider,
    DiscoveryFilter,
    KMSMasterKey,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
    MRKAwareKMSMasterKey,
    MRKAwareStrictAwsKmsMasterKeyProvider,
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
        self.mock_botocore_session_patcher = patch(
            "aws_encryption_sdk.key_providers.kms.botocore.session.Session", __class__=botocore.session.Session
        )
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
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# The input MUST be the same as the Master Key Provider Get Master Key
        # //# (../master-key-provider-interface.md#get-master-key) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# The output MUST be the same as the Master Key Provider Get Master Key
        # //# (../master-key-provider-interface.md#get-master-key) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
        # //= type=test
        # //# The input MUST be the same as the Master Key Provider Get Master Keys
        # //# For Encryption (../master-key-provider-interface.md#get-master-keys-
        # //# for-encryption) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
        # //= type=test
        # //# The output MUST be the same as the Master Key Provider Get Master
        # //# Keys For Encryption (../master-key-provider-interface.md#get-master-
        # //# keys-for-encryption) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        # //= type=test
        # //# The input MUST be the same as the Master Key Provider Decrypt Data
        # //# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        # //= type=test
        # //# The output MUST be the same as the Master Key Provider Decrypt Data
        # //# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.5
        # //= type=test
        # //# MUST implement the Master Key Provider Interface (../master-key-
        # //# provider-interface.md#interface)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# The output MUST be the same as the Master Key Decrypt Data Key
        # //# (../master-key-interface.md#decrypt-data-key) interface.
        assert issubclass(BaseKMSMasterKeyProvider, MasterKeyProvider)

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider.add_regional_clients_from_list")
    def test_init_with_region_names(self, mock_add_clients):
        region_names = (sentinel.region_name_1, sentinel.region_name_2)
        test = UnitTestBaseKMSMasterKeyProvider(region_names=region_names)
        mock_add_clients.assert_called_once_with(region_names)
        assert test.default_region is sentinel.region_name_1
        assert test.config.grant_tokens == ()

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

    def test_init_with_grant_tokens(self):
        grant_tokens = (sentinel.grant_token2, sentinel.grant_token2)
        test = UnitTestBaseKMSMasterKeyProvider(grant_tokens=grant_tokens)
        test._process_config()
        assert test.config.grant_tokens is grant_tokens

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
        assert key.config.grant_tokens == ()

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
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# In discovery mode if a discovery filter is configured the requested AWS
        # //# KMS key ARN's "partition" MUST match the discovery filter's
        # //# "partition" and the AWS KMS key ARN's "account" MUST exist in the
        # //# discovery filter's account id set.
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

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_new_master_key_with_grant_tokens(self, mock_client):
        grant_tokens = (sentinel.grant_token2, sentinel.grant_token2)
        mock_client.return_value = self.mock_boto3_client_instance
        key_info = b"arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        test = UnitTestBaseKMSMasterKeyProvider(key_ids=[key_info], grant_tokens=grant_tokens)

        key = test._new_master_key(key_info)
        assert key.key_id == key_info
        assert key.config.grant_tokens is grant_tokens


class TestDiscoveryKMSMasterKeyProvider(KMSMasterKeyProviderTestBase):
    def test_parent(self):
        assert issubclass(DiscoveryAwsKmsMasterKeyProvider, BaseKMSMasterKeyProvider)

    def test_init_bare(self):
        test = DiscoveryAwsKmsMasterKeyProvider()
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
        # //= type=test
        # //# If the configured mode is discovery the function MUST return an empty
        # //# list.
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
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# The key id list MUST be empty in discovery mode.
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(
                discovery_filter=DiscoveryFilter(account_ids=["123"], partition="aws"), key_ids=["1234"]
            )
        excinfo.match("To explicitly identify which keys should be used, use a StrictAwsKmsMasterKeyProvider.")

    def test_init_failure_with_discovery_region(self):
        with pytest.raises(ConfigMismatchError) as excinfo:
            DiscoveryAwsKmsMasterKeyProvider(discovery_region="us-west-2")
        excinfo.match("To enable MRK-aware discovery mode, use a MRKAwareDiscoveryAwsKmsMasterKeyProvider.")

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
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# The key id list MUST NOT be empty or null in strict mode.
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=[])
        excinfo.match("To enable strict mode you must provide key ids")

    def test_init_null_key_id_fails(self):
        key_ids = ("arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", None)
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        excinfo.match("Key ids must be valid AWS KMS ARNs")

    def test_init_empty_string_key_id_fails(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# The key id list MUST NOT contain any null or empty string values.
        key_ids = ("arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", "")
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        excinfo.match("Key ids must be valid AWS KMS ARNs")

    @patch("aws_encryption_sdk.key_providers.kms.StrictAwsKmsMasterKeyProvider.add_master_keys_from_list")
    def test_init_with_discovery_fails(self, mock_add_keys):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# A discovery filter MUST NOT be configured in strict mode.
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
    def test_init_with_discovery_region_fails(self, mock_add_keys):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# A default MRK Region MUST NOT be configured in strict mode.
        key_ids = (
            "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:us-east-1:333333333333:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        )
        with pytest.raises(ConfigMismatchError) as excinfo:
            StrictAwsKmsMasterKeyProvider(key_ids=key_ids, discovery_region="us-east-1")
        excinfo.match("To enable MRK-aware discovery mode, use a MRKAwareDiscoveryAwsKmsMasterKeyProvider")
        mock_add_keys.assert_not_called()

    @patch("aws_encryption_sdk.key_providers.kms.StrictAwsKmsMasterKeyProvider.add_master_keys_from_list")
    def test_init_with_key_ids(self, mock_add_keys):
        key_ids = (
            "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:us-east-1:333333333333:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        )
        test = StrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
        # //= type=test
        # //# If the configured mode is strict this function MUST return a
        # //# list of master keys obtained by calling Get Master Key (aws-kms-mrk-
        # //# aware-master-key-provider.md#get-master-key) for each AWS KMS key
        # //# identifier in the configured key ids
        assert not test.vend_masterkey_on_decrypt
        mock_add_keys.assert_called_once_with(key_ids)

    @patch("aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider._client")
    def test_add_master_keys_class(self, mock_client):
        """Check that the MRK-aware provider creates MRKAwareKMSMasterKeys"""
        mock_client.return_value = self.mock_boto3_client_instance
        key_id = "arn:aws:kms:eu-west-2:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        provider = StrictAwsKmsMasterKeyProvider(key_ids=[key_id])
        master_key = provider._new_master_key(key_id)
        assert master_key.__class__ == KMSMasterKey


class TestMRKAwareStrictKMSMasterKeyProvider(KMSMasterKeyProviderTestBase):
    def test_parent(self):
        assert issubclass(MRKAwareStrictAwsKmsMasterKeyProvider, StrictAwsKmsMasterKeyProvider)

    def test_init_with_key_ids(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# All AWS KMS
        # //# key identifiers are be passed to Assert AWS KMS MRK are unique (aws-
        # //# kms-mrk-are-unique.md#Implementation) and the function MUST return
        # //# success.

        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //= type=test
        # //# The caller MUST provide:

        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //= type=test
        # //# If there are zero duplicate resource ids between the multi-region
        # //# keys, this function MUST exit successfully
        key_ids = (
            "arn:aws:kms:eu-west-2:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:us-east-1:222222222222:key/mrk-bbbbbbbb-1111-2222-3333-bbbbbbbbbbbb",
        )
        provider = MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=key_ids)
        assert len(provider.config.key_ids) == 2
        assert key_ids[0] in provider.config.key_ids
        assert key_ids[1] in provider.config.key_ids

    def test_init_with_duplicate_non_mrk_key_ids(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //= type=test
        # //# If the list does not contain any multi-Region keys (aws-kms-key-
        # //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
        # //# exit successfully.
        key_ids = (
            "arn:aws:kms:eu-west-2:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:eu-west-2:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "alias/myAlias",
            "alias/myAlias",
        )
        with patch.object(self.mock_botocore_session, "get_config_variable", return_value="us-west-2"):
            provider = MRKAwareStrictAwsKmsMasterKeyProvider(
                botocore_session=self.mock_botocore_session, key_ids=key_ids
            )
            assert len(provider.config.key_ids) == 4
            assert key_ids[0] in provider.config.key_ids
            assert key_ids[1] in provider.config.key_ids
            assert key_ids[2] in provider.config.key_ids
            assert key_ids[3] in provider.config.key_ids

    def test_init_requires_unique_mrks(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //= type=test
        # //# If any duplicate multi-region resource ids exist, this function MUST
        # //# yield an error that includes all identifiers with duplicate resource
        # //# ids not only the first duplicate found.
        key_ids = (
            "arn:aws:kms:eu-west-2:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:us-east-1:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:eu-west-2:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        )
        expected_error_string = "Configured key ids must be unique. Found related MRKs: .*, .*, .*"
        with patch.object(self.mock_botocore_session, "get_config_variable", return_value="us-west-2"):
            with pytest.raises(ConfigMismatchError) as excinfo:
                MRKAwareStrictAwsKmsMasterKeyProvider(botocore_session=self.mock_botocore_session, key_ids=key_ids)
            excinfo.match(expected_error_string)

    def test_add_master_keys_class(self):
        """Check that the MRK-aware provider creates MRKAwareKMSMasterKeys"""
        grant_tokens = (sentinel.grant_token2, sentinel.grant_token2)
        key_id = "arn:aws:kms:eu-west-2:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        provider = MRKAwareStrictAwsKmsMasterKeyProvider(key_ids=[key_id], grant_tokens=grant_tokens)

        master_key = provider._new_master_key(key_id)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# In strict mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
        # //# master-key.md) MUST be returned configured with
        assert master_key.__class__ == MRKAwareKMSMasterKey
        assert "eu-west-2" in master_key._key_id
        self.mock_boto3_session.assert_called_with(botocore_session=ANY)
        self.mock_boto3_session_instance.client.assert_called_with(
            "kms",
            region_name="eu-west-2",
            config=provider._user_agent_adding_config,
        )
        assert master_key.config.grant_tokens is grant_tokens

    @pytest.mark.parametrize(
        "non_arn",
        (
            "alias/myAlias",
            "mrk-1234",
            "1234",
        ),
    )
    def test_add_master_keys_invalid_arn(self, non_arn):
        """
        Check that the Strict MRK-aware provider uses the default region when creating a new key with an invalid arn.
        """
        with patch.object(
            self.mock_botocore_session, "get_config_variable", return_value="us-west-2"
        ) as mock_get_config:
            provider = MRKAwareStrictAwsKmsMasterKeyProvider(
                botocore_session=self.mock_botocore_session, key_ids=[non_arn]
            )
            master_key = provider._new_master_key(non_arn)

            mock_get_config.assert_called_with("region")
            assert master_key.__class__ == MRKAwareKMSMasterKey
            assert master_key._key_id == non_arn
            self.mock_boto3_session.assert_called_with(botocore_session=ANY)
            self.mock_boto3_session_instance.client.assert_called_with(
                "kms",
                region_name="us-west-2",
                config=provider._user_agent_adding_config,
            )


class TestMRKAwareDiscoveryKMSMasterKeyProvider(KMSMasterKeyProviderTestBase):
    def test_parent(self):
        assert issubclass(MRKAwareDiscoveryAwsKmsMasterKeyProvider, DiscoveryAwsKmsMasterKeyProvider)

    def test_init_explicit_discovery_region(self):
        provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(discovery_region="us-east-1")
        assert provider.config.discovery_region == "us-east-1"

    def test_init_implicit_discovery_region(self):
        """Check that an MRK-aware provider without an explicit discovery_region uses the default SDK region."""
        with patch.object(
            self.mock_botocore_session, "get_config_variable", return_value=sentinel.default_region
        ) as mock_get_config:
            test = MRKAwareDiscoveryAwsKmsMasterKeyProvider(botocore_session=self.mock_botocore_session)
            mock_get_config.assert_called_once_with("region")
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
            # //= type=test
            # //# In discovery mode
            # //# if a default MRK Region is not configured the AWS SDK Default Region
            # //# MUST be used.
            assert test.default_region is sentinel.default_region
            assert test.config.discovery_region is sentinel.default_region

    def test_init_sdk_default_not_found(self):
        """Check that an MRK-aware provider without an explicit discovery_region fails to initialize if it cannot
        find a default region for the AWS SDK."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //= type=test
        # //# If an AWS SDK Default Region can not be obtained
        # //# initialization MUST fail.
        with pytest.raises(ConfigMismatchError) as excinfo:
            MRKAwareDiscoveryAwsKmsMasterKeyProvider(botocore_session=self.botocore_no_region_session)
        excinfo.match("Failed to determine default discovery region")

    def test_add_master_keys_mrk_with_discovery_region(self):
        """Check that an MRK-aware provider with an explicit discovery_region uses its configured region when creating
        new keys if the requested keys are MRKs."""
        grant_tokens = (sentinel.grant_token2, sentinel.grant_token2)
        original_arn = arn_from_str("arn:aws:kms:eu-west-2:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")
        configured_region = "us-east-1"
        provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(
            discovery_region=configured_region, grant_tokens=grant_tokens
        )
        master_key = provider._new_master_key(original_arn.to_string())

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# In discovery mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
        # //# master-key.md) MUST be returned configured with
        assert master_key.__class__ == MRKAwareKMSMasterKey
        self.mock_boto3_session.assert_called_with(botocore_session=ANY)
        self.mock_boto3_session_instance.client.assert_called_with(
            "kms",
            region_name=configured_region,
            config=provider._user_agent_adding_config,
        )
        assert configured_region in master_key._key_id
        assert original_arn.region not in master_key._key_id
        assert master_key.config.grant_tokens is grant_tokens

    def test_add_master_keys_mrk_sdk_default(self):
        """Check that an MRK-aware provider without an explicit discovery_region uses its default region when creating
        new keys if the requested keys are MRKs."""
        grant_tokens = (sentinel.grant_token2, sentinel.grant_token2)
        original_arn = arn_from_str("arn:aws:kms:eu-west-2:222222222222:key/mrk-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")
        with patch.object(
            self.mock_botocore_session, "get_config_variable", return_value="us-west-2"
        ) as mock_get_config:
            provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(
                botocore_session=self.mock_botocore_session, grant_tokens=grant_tokens
            )
            mock_get_config.assert_called_once_with("region")

            master_key = provider._new_master_key(original_arn.to_string())

            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            # //= type=test
            # //# Otherwise if the mode is discovery then
            # //# the AWS Region MUST be the discovery MRK region.

            assert master_key.__class__ == MRKAwareKMSMasterKey
            self.mock_boto3_session.assert_called_with(botocore_session=ANY)
            self.mock_boto3_session_instance.client.assert_called_with(
                "kms",
                region_name=provider.default_region,
                config=provider._user_agent_adding_config,
            )
            assert provider.default_region in master_key._key_id
            assert original_arn.region not in master_key._key_id
            assert master_key.config.grant_tokens is grant_tokens

    def test_add_master_keys_srk(self):
        """Check that the MRK-aware provider uses the original key region when creating new keys if the requested
        keys are SRKs."""
        original_arn = "arn:aws:kms:eu-west-2:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(discovery_region="us-east-1")
        master_key = provider._new_master_key(original_arn)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# Otherwise if the requested AWS KMS key
        # //# identifier is identified as a multi-Region key (aws-kms-key-
        # //# arn.md#identifying-an-aws-kms-multi-region-key), then AWS Region MUST
        # //# be the region from the AWS KMS key ARN stored in the provider info
        # //# from the encrypted data key.
        assert master_key.__class__ == MRKAwareKMSMasterKey
        self.mock_boto3_session.assert_called_with(botocore_session=ANY)
        self.mock_boto3_session_instance.client.assert_called_with(
            "kms",
            region_name="eu-west-2",
            config=provider._user_agent_adding_config,
        )
        assert master_key._key_id == original_arn

    @pytest.mark.parametrize(
        "non_arn",
        (
            "alias/myAlias",
            "mrk-1234",
            "1234",
            ":aws:kms:eu-west-2:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "arn:aws:kms:eu-west-2:222222222222:key/",
        ),
    )
    def test_add_master_keys_invalid_arn(self, non_arn):
        """Check that the provider throws an error when creating a new key with an invalid arn."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=test
        # //# In discovery mode, the requested
        # //# AWS KMS key identifier MUST be a well formed AWS KMS ARN.

        provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(discovery_region="us-east-1")
        with pytest.raises(MalformedArnError):
            provider._new_master_key(non_arn)
