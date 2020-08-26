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
"""Unit test suite for aws_encryption_sdk.key_providers.kms.KMSMasterKey"""
import botocore.client
import pytest
from botocore.exceptions import ClientError
from mock import MagicMock, patch, sentinel

from aws_encryption_sdk.exceptions import DecryptKeyError, EncryptKeyError, GenerateKeyError
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.key_providers.base import MasterKey
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyConfig
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestKMSMasterKey(object):
    @pytest.fixture(autouse=True)
    def apply_fixture(self):
        self.mock_client = MagicMock()
        self.mock_client.__class__ = botocore.client.BaseClient
        self.mock_client.generate_data_key.return_value = {
            "Plaintext": VALUES["data_key"],
            "CiphertextBlob": VALUES["encrypted_data_key"],
            "KeyId": VALUES["arn_str"],
        }
        self.mock_client.encrypt.return_value = {"CiphertextBlob": VALUES["encrypted_data_key"], "KeyId": VALUES["arn"]}
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"], "KeyId": VALUES["arn_str"]}
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.__class__ = Algorithm
        self.mock_algorithm.data_key_len = sentinel.data_key_len
        self.mock_algorithm.kdf_input_len = sentinel.kdf_input_len
        self.mock_data_key = MagicMock()
        self.mock_data_key.data_key = VALUES["data_key"]
        self.mock_encrypted_data_key = MagicMock()
        self.mock_encrypted_data_key.encrypted_data_key = VALUES["encrypted_data_key"]
        self.mock_encrypted_data_key.key_provider.key_info = VALUES["arn_str"]

        self.mock_data_key_len_check_patcher = patch("aws_encryption_sdk.internal.utils.source_data_key_length_check")
        self.mock_data_key_len_check = self.mock_data_key_len_check_patcher.start()

        self.mock_grant_tokens = (sentinel.grant_token_1, sentinel.grant_token_2)
        self.mock_kms_mkc_1 = KMSMasterKeyConfig(key_id=VALUES["arn"], client=self.mock_client)
        self.mock_kms_mkc_2 = KMSMasterKeyConfig(
            key_id=VALUES["arn"], client=self.mock_client, grant_tokens=self.mock_grant_tokens
        )
        self.mock_kms_mkc_3 = KMSMasterKeyConfig(key_id="ex_key_info", client=self.mock_client)
        yield
        # Run tearDown
        self.mock_data_key_len_check_patcher.stop()

    def test_parent(self):
        assert issubclass(KMSMasterKey, MasterKey)

    def test_config_bare(self):
        test = KMSMasterKeyConfig(key_id=VALUES["arn"], client=self.mock_client)
        assert test.client is self.mock_client
        assert test.grant_tokens == ()

    def test_config_grant_tokens(self):
        test = KMSMasterKeyConfig(key_id=VALUES["arn"], client=self.mock_client, grant_tokens=self.mock_grant_tokens)
        assert test.grant_tokens is self.mock_grant_tokens

    def test_init(self):
        self.mock_client.meta.config.user_agent_extra = sentinel.user_agent_extra
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        assert test._key_id == VALUES["arn"].decode("utf-8")

    def test_generate_data_key(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        generated_key = test._generate_data_key(self.mock_algorithm)
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId="ex_key_info", NumberOfBytes=sentinel.kdf_input_len
        )
        assert generated_key == DataKey(
            key_provider=MasterKeyInfo(provider_id=test.provider_id, key_info=VALUES["arn"]),
            data_key=VALUES["data_key"],
            encrypted_data_key=VALUES["encrypted_data_key"],
        )

    def test_generate_data_key_with_encryption_context(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        test._generate_data_key(self.mock_algorithm, VALUES["encryption_context"])
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=VALUES["arn_str"],
            NumberOfBytes=sentinel.kdf_input_len,
            EncryptionContext=VALUES["encryption_context"],
        )

    def test_generate_data_key_with_grant_tokens(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_2)
        test._generate_data_key(self.mock_algorithm)
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=VALUES["arn_str"], NumberOfBytes=sentinel.kdf_input_len, GrantTokens=self.mock_grant_tokens
        )

    def test_generate_data_key_unsuccessful_clienterror(self):
        self.mock_client.generate_data_key.side_effect = ClientError({"Error": {}}, "This is an error!")
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with pytest.raises(GenerateKeyError) as excinfo:
            test._generate_data_key(self.mock_algorithm)
        excinfo.match("Master Key .* unable to generate data key")

    def test_generate_data_key_unsuccessful_keyerror(self):
        self.mock_client.generate_data_key.side_effect = KeyError
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with pytest.raises(GenerateKeyError) as excinfo:
            test._generate_data_key(self.mock_algorithm)
        excinfo.match("Master Key .* unable to generate data key")

    def test_encrypt_data_key(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        encrypted_key = test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        self.mock_client.encrypt.assert_called_once_with(KeyId="ex_key_info", Plaintext=VALUES["data_key"])
        assert encrypted_key == EncryptedDataKey(
            key_provider=MasterKeyInfo(provider_id=test.provider_id, key_info=VALUES["arn"]),
            encrypted_data_key=VALUES["encrypted_data_key"],
        )

    def test_encrypt_data_key_with_encryption_context(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        test._encrypt_data_key(self.mock_data_key, self.mock_algorithm, VALUES["encryption_context"])
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=VALUES["arn_str"], Plaintext=VALUES["data_key"], EncryptionContext=VALUES["encryption_context"]
        )

    def test_encrypt_data_key_with_grant_tokens(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_2)
        test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=VALUES["arn_str"], Plaintext=VALUES["data_key"], GrantTokens=self.mock_grant_tokens
        )

    def test_encrypt_data_key_unsuccessful_clienterror(self):
        self.mock_client.encrypt.side_effect = ClientError({"Error": {}}, "This is an error!")
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with pytest.raises(EncryptKeyError) as excinfo:
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        excinfo.match("Master Key .* unable to encrypt data key")

    def test_encrypt_data_key_unsuccessful_keyerror(self):
        self.mock_client.encrypt.side_effect = KeyError
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with pytest.raises(EncryptKeyError) as excinfo:
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        excinfo.match("Master Key .* unable to encrypt data key")

    def test_decrypt_data_key(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        decrypted_key = test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm
        )
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"], KeyId=VALUES["arn_str"]
        )
        assert decrypted_key == DataKey(
            key_provider=test.key_provider, data_key=VALUES["data_key"], encrypted_data_key=VALUES["encrypted_data_key"]
        )

    def test_decrypt_data_key_with_encryption_context(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=VALUES["encryption_context"],
        )
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"],
            EncryptionContext=VALUES["encryption_context"],
            KeyId=VALUES["arn_str"],
        )

    def test_decrypt_data_key_with_grant_tokens(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_2)
        test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"], GrantTokens=self.mock_grant_tokens, KeyId=VALUES["arn_str"]
        )

    def test_decrypt_data_key_unsuccessful_clienterror(self):
        self.mock_client.decrypt.side_effect = ClientError({"Error": {}}, "This is an error!")
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("Master Key .* unable to decrypt data key")

    def test_decrypt_data_key_unsuccessful_keyerror(self):
        self.mock_client.decrypt.side_effect = KeyError
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("Master Key .* unable to decrypt data key")

    def test_decrypt_data_key_unsuccessful_key_id_does_not_match_edk(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("does not match this provider's key_id")

        self.mock_client.assert_not_called()

    def test_decrypt_data_key_unsuccessful_response_missing_key_id(self):
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"]}

        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("Master Key .* unable to decrypt data key")

        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"], KeyId=VALUES["arn_str"]
        )

    def test_decrypt_data_key_unsuccessful_mismatched_key_id(self):
        mismatched_key_id = VALUES["arn_str"] + "-test"
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"], "KeyId": mismatched_key_id}

        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("AWS KMS returned unexpected key_id")
