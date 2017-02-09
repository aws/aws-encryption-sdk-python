"""Unit test suite for aws_encryption_sdk.key_providers.kms.KMSMasterKey"""
import unittest

import botocore
import botocore.client
from botocore.exceptions import ClientError
from mock import MagicMock, sentinel, patch
import six

from aws_encryption_sdk.exceptions import GenerateKeyError, EncryptKeyError, DecryptKeyError
from aws_encryption_sdk.identifiers import Algorithm, __version__
from aws_encryption_sdk.key_providers.base import MasterKey
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyConfig
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey
from .test_values import VALUES


class TestKMSMasterKey(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.__class__ = botocore.client.BaseClient
        self.mock_client.generate_data_key.return_value = {
            'Plaintext': VALUES['data_key'],
            'CiphertextBlob': VALUES['encrypted_data_key']
        }
        self.mock_client.encrypt.return_value = {
            'CiphertextBlob': VALUES['encrypted_data_key']
        }
        self.mock_client.decrypt.return_value = {
            'Plaintext': VALUES['data_key']
        }
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.__class__ = Algorithm
        self.mock_algorithm.data_key_len = sentinel.data_key_len
        self.mock_algorithm.kdf_input_len = sentinel.kdf_input_len
        self.mock_data_key = MagicMock()
        self.mock_data_key.data_key = VALUES['data_key']
        self.mock_encrypted_data_key = MagicMock()
        self.mock_encrypted_data_key.encrypted_data_key = VALUES['encrypted_data_key']

        self.mock_data_key_len_check_patcher = patch('aws_encryption_sdk.internal.utils.source_data_key_length_check')
        self.mock_data_key_len_check = self.mock_data_key_len_check_patcher.start()

        self.mock_grant_tokens = [sentinel.grant_token_1, sentinel.grant_token_2]
        self.mock_kms_mkc_1 = KMSMasterKeyConfig(
            key_id=VALUES['arn'],
            client=self.mock_client
        )
        self.mock_kms_mkc_2 = KMSMasterKeyConfig(
            key_id=VALUES['arn'],
            client=self.mock_client,
            grant_tokens=self.mock_grant_tokens
        )
        self.mock_kms_mkc_3 = KMSMasterKeyConfig(
            key_id='ex_key_info',
            client=self.mock_client
        )

    def test_parent(self):
        assert issubclass(KMSMasterKey, MasterKey)

    def tearDown(self):
        self.mock_data_key_len_check_patcher.stop()

    def test_config_bare(self):
        test = KMSMasterKeyConfig(
            key_id=VALUES['arn'],
            client=self.mock_client
        )
        assert test.client is self.mock_client
        assert test.grant_tokens == []

    def test_config_grant_tokens(self):
        test = KMSMasterKeyConfig(
            key_id=VALUES['arn'],
            client=self.mock_client,
            grant_tokens=self.mock_grant_tokens
        )
        assert test.grant_tokens is self.mock_grant_tokens

    def test_init(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        assert test._key_id == VALUES['arn'].decode('utf-8')
        assert self.mock_client.meta.config.user_agent == 'Botocore-KMSMasterKey/{}/{}'.format(
            __version__,
            botocore.__version__
        )

    def test_generate_data_key(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        generated_key = test._generate_data_key(self.mock_algorithm)
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=VALUES['arn_str'],
            NumberOfBytes=sentinel.kdf_input_len
        )
        assert generated_key == DataKey(
            key_provider=test.key_provider,
            data_key=VALUES['data_key'],
            encrypted_data_key=VALUES['encrypted_data_key']
        )

    def test_generate_data_key_with_encryption_context(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        test._generate_data_key(self.mock_algorithm, VALUES['encryption_context'])
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=VALUES['arn_str'],
            NumberOfBytes=sentinel.kdf_input_len,
            EncryptionContext=VALUES['encryption_context']
        )

    def test_generate_data_key_with_grant_tokens(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_2)
        test._generate_data_key(self.mock_algorithm)
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=VALUES['arn_str'],
            NumberOfBytes=sentinel.kdf_input_len,
            GrantTokens=self.mock_grant_tokens
        )

    def test_generate_data_key_unsuccessful_clienterror(self):
        self.mock_client.generate_data_key.side_effect = ClientError({'Error': {}}, 'This is an error!')
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with six.assertRaisesRegex(self, GenerateKeyError, 'Master Key .* unable to generate data key'):
            test._generate_data_key(self.mock_algorithm)

    def test_generate_data_key_unsuccessful_keyerror(self):
        self.mock_client.generate_data_key.side_effect = KeyError
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with six.assertRaisesRegex(self, GenerateKeyError, 'Master Key .* unable to generate data key'):
            test._generate_data_key(self.mock_algorithm)

    def test_encrypt_data_key(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        encrypted_key = test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=VALUES['arn_str'],
            Plaintext=VALUES['data_key']
        )
        assert encrypted_key == EncryptedDataKey(
            key_provider=test.key_provider,
            encrypted_data_key=VALUES['encrypted_data_key']
        )

    def test_encrypt_data_key_with_encryption_context(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        test._encrypt_data_key(self.mock_data_key, self.mock_algorithm, VALUES['encryption_context'])
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=VALUES['arn_str'],
            Plaintext=VALUES['data_key'],
            EncryptionContext=VALUES['encryption_context']
        )

    def test_encrypt_data_key_with_grant_tokens(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_2)
        test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=VALUES['arn_str'],
            Plaintext=VALUES['data_key'],
            GrantTokens=self.mock_grant_tokens
        )

    def test_encrypt_data_key_unsuccessful_clienterror(self):
        self.mock_client.encrypt.side_effect = ClientError({'Error': {}}, 'This is an error!')
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with six.assertRaisesRegex(self, EncryptKeyError, 'Master Key .* unable to encrypt data key'):
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)

    def test_encrypt_data_key_unsuccessful_keyerror(self):
        self.mock_client.encrypt.side_effect = KeyError
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with six.assertRaisesRegex(self, EncryptKeyError, 'Master Key .* unable to encrypt data key'):
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)

    def test_decrypt_data_key(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        decrypted_key = test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key,
            algorithm=sentinel.algorithm
        )
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES['encrypted_data_key']
        )
        assert decrypted_key == DataKey(
            key_provider=test.key_provider,
            data_key=VALUES['data_key'],
            encrypted_data_key=VALUES['encrypted_data_key']
        )

    def test_decrypt_data_key_with_encryption_context(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_1)
        test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=VALUES['encryption_context']
        )
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES['encrypted_data_key'],
            EncryptionContext=VALUES['encryption_context']
        )

    def test_decrypt_data_key_with_grant_tokens(self):
        test = KMSMasterKey(config=self.mock_kms_mkc_2)
        test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key,
            algorithm=sentinel.algorithm
        )
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES['encrypted_data_key'],
            GrantTokens=self.mock_grant_tokens
        )

    def test_decrypt_data_key_unsuccessful_clienterror(self):
        self.mock_client.decrypt.side_effect = ClientError({'Error': {}}, 'This is an error!')
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with six.assertRaisesRegex(self, DecryptKeyError, 'Master Key .* unable to decrypt data key'):
            test._decrypt_data_key(
                encrypted_data_key=self.mock_encrypted_data_key,
                algorithm=sentinel.algorithm
            )

    def test_decrypt_data_key_unsuccessful_keyerror(self):
        self.mock_client.decrypt.side_effect = KeyError
        test = KMSMasterKey(config=self.mock_kms_mkc_3)
        with six.assertRaisesRegex(self, DecryptKeyError, 'Master Key .* unable to decrypt data key'):
            test._decrypt_data_key(
                encrypted_data_key=self.mock_encrypted_data_key,
                algorithm=sentinel.algorithm
            )
