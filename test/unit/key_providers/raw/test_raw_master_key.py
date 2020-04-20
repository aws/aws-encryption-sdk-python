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
"""Test suite for aws_encryption_sdk.key_providers.raw.RawMasterKey"""
import pytest
from mock import MagicMock, patch, sentinel

from aws_encryption_sdk.identifiers import Algorithm, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKey
from aws_encryption_sdk.key_providers.raw import RawMasterKey, RawMasterKeyConfig
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo, RawDataKey

from ...vectors import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestRawMasterKey(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.__class__ = Algorithm
        self.mock_algorithm.data_key_len = sentinel.data_key_len
        self.mock_algorithm.kdf_input_len = sentinel.kdf_input_len
        self.mock_encrypted_data_key = EncryptedDataKey(
            key_provider=VALUES["key_provider"], encrypted_data_key=VALUES["encrypted_data_key"]
        )
        self.mock_data_key = DataKey(
            key_provider=VALUES["key_provider"],
            data_key=VALUES["data_key"],
            encrypted_data_key=VALUES["encrypted_data_key"],
        )
        self.mock_wrapping_algorithm = MagicMock()
        self.mock_wrapping_algorithm.__class__ = WrappingAlgorithm
        self.mock_wrapping_algorithm.encryption_type = sentinel.encryption_type
        self.mock_wrapping_key = MagicMock()
        self.mock_wrapping_key.__class__ = WrappingKey
        self.mock_wrapping_key.wrapping_algorithm = self.mock_wrapping_algorithm
        self.mock_wrapping_key.encrypt.return_value = sentinel.encrypted_data
        self.mock_wrapping_key.decrypt.return_value = VALUES["data_key"]

    def test_parent(self):
        assert issubclass(RawMasterKey, MasterKey)

    def test_config(self):
        test = RawMasterKeyConfig(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        assert test.provider_id == VALUES["provider_id"]
        assert test.wrapping_key is self.mock_wrapping_key

    def test_init(self):
        test = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        assert test.provider_id == VALUES["provider_id"]

    @patch("aws_encryption_sdk.internal.utils.source_data_key_length_check")
    @patch("aws_encryption_sdk.key_providers.raw.os.urandom")
    @patch("aws_encryption_sdk.key_providers.raw.RawMasterKey._encrypt_data_key")
    def test_generate_data_key(self, mock_encrypt_data_key, mock_urandom, mock_key_len_check):
        mock_urandom.return_value = VALUES["data_key"]
        mock_encrypt_data_key.return_value = self.mock_encrypted_data_key
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        test = test_master_key.generate_data_key(
            algorithm=self.mock_algorithm, encryption_context=VALUES["encryption_context"]
        )
        mock_urandom.assert_called_once_with(sentinel.kdf_input_len)
        mock_encrypt_data_key.assert_called_once_with(
            data_key=RawDataKey(key_provider=test_master_key.key_provider, data_key=VALUES["data_key"]),
            algorithm=self.mock_algorithm,
            encryption_context=VALUES["encryption_context"],
        )
        assert test == self.mock_data_key

    @patch("aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key", return_value=sentinel.wrapped_key)
    def test_encrypt_data_key(self, mock_wrapped_serialize):
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        test = test_master_key._encrypt_data_key(
            data_key=self.mock_data_key, algorithm=sentinel.algorithm, encryption_context=sentinel.encryption_context
        )
        self.mock_wrapping_key.encrypt.assert_called_once_with(
            plaintext_data_key=VALUES["data_key"], encryption_context=sentinel.encryption_context
        )
        mock_wrapped_serialize.assert_called_once_with(
            key_provider=test_master_key.key_provider,
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            encrypted_wrapped_key=sentinel.encrypted_data,
        )
        assert test is sentinel.wrapped_key

    @patch(
        "aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key",
        return_value=sentinel.encrypted_wrapped_key,
    )
    def test_decrypt_data_key(self, mock_wrapped_deserialize):
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        test = test_master_key._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key,
            algorithm=self.mock_algorithm,
            encryption_context=sentinel.encryption_context,
        )
        mock_wrapped_deserialize.assert_called_once_with(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            wrapped_encrypted_key=self.mock_encrypted_data_key,
        )
        self.mock_wrapping_key.decrypt.assert_called_once_with(
            encrypted_wrapped_data_key=sentinel.encrypted_wrapped_key, encryption_context=sentinel.encryption_context
        )
        assert test == self.mock_data_key

    def test_owns_data_key_owned_asymmetric(self):
        self.mock_wrapping_key.wrapping_algorithm = WrappingAlgorithm.RSA_OAEP_SHA1_MGF1
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        assert test_master_key.owns_data_key(
            data_key=DataKey(
                key_provider=MasterKeyInfo(
                    provider_id=VALUES["provider_id"], key_info=VALUES["wrapped_keys"]["raw"]["key_info"]
                ),
                encrypted_data_key=VALUES["encrypted_data_key"],
                data_key=VALUES["data_key"],
            )
        )

    @patch(
        "aws_encryption_sdk.internal.formatting.serialize.serialize_raw_master_key_prefix",
        return_value=VALUES["wrapped_keys"]["serialized"]["key_info_prefix"],
    )
    def test_owns_data_key_owned_symmetric(self, mock_prefix):
        self.mock_wrapping_key.wrapping_algorithm = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        assert test_master_key.owns_data_key(
            data_key=DataKey(
                key_provider=MasterKeyInfo(
                    provider_id=VALUES["provider_id"], key_info=VALUES["wrapped_keys"]["serialized"]["key_info"]
                ),
                encrypted_data_key=VALUES["encrypted_data_key"],
                data_key=VALUES["data_key"],
            )
        )

    def test_owns_data_key_not_owned_symmetric_mismatch(self):
        self.mock_wrapping_key.wrapping_algorithm = WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        assert not test_master_key.owns_data_key(
            data_key=DataKey(
                key_provider=MasterKeyInfo(
                    provider_id=VALUES["provider_id"],
                    key_info=VALUES["wrapped_keys"]["serialized"]["key_info_symmetric_nonmatch"],
                ),
                encrypted_data_key=VALUES["encrypted_data_key"],
                data_key=VALUES["data_key"],
            )
        )

    def test_owns_data_key_not_owned_asymmetric_checking_symmetric(self):
        self.mock_wrapping_key.wrapping_algorithm = WrappingAlgorithm.RSA_OAEP_SHA1_MGF1
        test_master_key = RawMasterKey(
            key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            provider_id=VALUES["provider_id"],
            wrapping_key=self.mock_wrapping_key,
        )
        assert not test_master_key.owns_data_key(
            data_key=DataKey(
                key_provider=MasterKeyInfo(
                    provider_id=VALUES["provider_id"], key_info=VALUES["wrapped_keys"]["serialized"]["key_info"]
                ),
                encrypted_data_key=VALUES["encrypted_data_key"],
                data_key=VALUES["data_key"],
            )
        )
