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
"""Test suite for aws_encryption_sdk.key_providers.base.MasterKey"""
import unittest

import attr
from mock import MagicMock, patch, sentinel
import pytest
import six

from aws_encryption_sdk.exceptions import ConfigMismatchError, IncorrectMasterKeyError, InvalidKeyIdError
from aws_encryption_sdk.internal.defaults import ALGORITHM
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig, MasterKeyProvider
from aws_encryption_sdk.structures import MasterKeyInfo
from .test_values import VALUES


@attr.s(hash=True)
class MockMasterKeyConfig(MasterKeyConfig):
    provider_id = VALUES['provider_id']
    mock_generated_data_key = attr.ib()
    mock_encrypted_data_key = attr.ib()
    mock_decrypted_data_key = attr.ib()


class MockMasterKey(MasterKey):
    _config_class = MockMasterKeyConfig
    provider_id = VALUES['provider_id']

    def _generate_data_key(self, algorithm, encryption_context):
        return self.config.mock_generated_data_key

    def _encrypt_data_key(self, data_key, algorithm, encryption_context):
        return self.config.mock_encrypted_data_key

    def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        return self.config.mock_decrypted_data_key


def test_master_key_provider_id_config_enforcement():
    class FakeConfig(object):
        key_id = b'a key'

    class FakeMasterKey(MockMasterKey):
        _config_class = FakeConfig

    with pytest.raises(TypeError) as excinfo:
        FakeMasterKey()

    excinfo.match(r'MasterKey config classes must have a "provider_id" attribute defined.')


class TestMasterKey(unittest.TestCase):

    def setUp(self):
        self.mock_data_key_len_check_patcher = patch('aws_encryption_sdk.internal.utils.source_data_key_length_check')
        self.mock_data_key_len_check = self.mock_data_key_len_check_patcher.start()

    def tearDown(self):
        self.mock_data_key_len_check_patcher.stop()

    def test_parent(self):
        assert issubclass(MasterKey, MasterKeyProvider)

    def test_provider_id_enforcement(self):
        class TestMasterKey(MasterKey):
            def _generate_data_key(self, algorithm, encryption_context):
                pass

            def _encrypt_data_key(self, data_key, algorithm, encryption_context):
                pass

            def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
                pass
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestMasterKey *"
        ):
            TestMasterKey()

    def test_generate_data_key_enforcement(self):
        class TestMasterKey(MasterKey):
            provider_id = None

            def _encrypt_data_key(self, data_key, algorithm, encryption_context):
                pass

            def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
                pass
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestMasterKey *"
        ):
            TestMasterKey()

    def test_encrypt_data_key_enforcement(self):
        class TestMasterKey(MasterKey):
            provider_id = None

            def _generate_data_key(self, algorithm, encryption_context):
                pass

            def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
                pass
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestMasterKey *"
        ):
            TestMasterKey()

    def test_decrypt_data_key_enforcement(self):
        class TestMasterKey(MasterKey):
            provider_id = None

            def _generate_data_key(self, algorithm, encryption_context):
                pass

            def _encrypt_data_key(self, data_key, algorithm, encryption_context):
                pass
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestMasterKey *"
        ):
            TestMasterKey()

    def test_new(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        assert mock_master_key.key_id is VALUES['key_info']
        assert mock_master_key.key_provider.provider_id == VALUES['provider_id']
        assert mock_master_key.key_provider.key_info is VALUES['key_info']

    def test_new_conf_mismatch(self):
        mock_config = MagicMock()
        mock_config.__class__ = MockMasterKeyConfig
        mock_config.provider_id = sentinel.mismatched_provider_id
        with six.assertRaisesRegex(
            self,
            ConfigMismatchError,
            'Config provider_id does not match MasterKey provider_id: *'
        ):
            MockMasterKey(config=mock_config)

    def test_owns_data_key_owned(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_data_key = MagicMock()
        mock_data_key.key_provider = mock_master_key.key_provider
        assert mock_master_key.owns_data_key(data_key=mock_data_key)

    def test_owns_data_key_not_owned(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_data_key = MagicMock()
        mock_data_key.key_provider = sentinel.key_provider
        assert not mock_master_key.owns_data_key(data_key=mock_data_key)

    def test_key_index(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        assert mock_master_key._encrypt_key_index == {VALUES['key_info']: mock_master_key}
        assert mock_master_key._decrypt_key_index == {}

    def test_members(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        assert mock_master_key._members == [mock_master_key]

    def test_master_keys_for_encryption(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        test_primary, test = mock_master_key.master_keys_for_encryption(
            encryption_context=sentinel.encryption_context,
            plaintext_rostream=sentinel.plaintext_rostream,
            plaintext_length=sentinel.plaintext_length
        )
        assert test_primary is mock_master_key
        assert test == [mock_master_key]

    def test_new_master_key_valid(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        test = mock_master_key._new_master_key(VALUES['key_info'])
        assert test is mock_master_key

    def test_new_master_key_invalid(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        with six.assertRaisesRegex(self, InvalidKeyIdError, 'MasterKeys can only provide themselves. *'):
            mock_master_key._new_master_key(sentinel.another_key_id)

    def test_key_check_valid(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_data_key = MagicMock()
        mock_data_key.key_provider = MasterKeyInfo(VALUES['provider_id'], VALUES['key_info'])
        mock_master_key._key_check(mock_data_key)

    def test_key_check_invalid(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_data_key = MagicMock()
        mock_data_key.key_provider = sentinel.another_key_provider
        with six.assertRaisesRegex(self, IncorrectMasterKeyError, 'Provided data key provider *'):
            mock_master_key._key_check(mock_data_key)

    def test_generate_data_key(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_master_key._generate_data_key = MagicMock(return_value=sentinel.new_raw_data_key)

        test = mock_master_key.generate_data_key(
            algorithm=ALGORITHM,
            encryption_context=VALUES['encryption_context']
        )

        mock_master_key._generate_data_key.assert_called_once_with(
            algorithm=ALGORITHM,
            encryption_context=VALUES['encryption_context']
        )
        self.mock_data_key_len_check.assert_called_once_with(
            source_data_key=sentinel.new_raw_data_key,
            algorithm=ALGORITHM
        )
        assert test is sentinel.new_raw_data_key

    def test_encrypt_data_key(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_master_key._key_check = MagicMock()
        mock_master_key._encrypt_data_key = MagicMock()

        mock_master_key.encrypt_data_key(
            data_key=sentinel.data_key,
            algorithm=ALGORITHM,
            encryption_context=VALUES['encryption_context']
        )

        mock_master_key._encrypt_data_key.assert_called_once_with(
            data_key=sentinel.data_key,
            algorithm=ALGORITHM,
            encryption_context=VALUES['encryption_context']
        )

    def test_decrypt_data_key(self):
        mock_master_key = MockMasterKey(
            key_id=VALUES['key_info'],
            mock_generated_data_key=sentinel.generated_data_key,
            mock_encrypted_data_key=sentinel.encrypted_data_key,
            mock_decrypted_data_key=sentinel.decrypted_data_key
        )
        mock_master_key._key_check = MagicMock()
        mock_master_key._decrypt_data_key = MagicMock(return_value=sentinel.raw_decrypted_data_key)

        mock_master_key.decrypt_data_key(
            encrypted_data_key=sentinel.encrypted_data_key,
            algorithm=ALGORITHM,
            encryption_context=VALUES['encryption_context']
        )

        self.mock_data_key_len_check.assert_called_once_with(
            source_data_key=sentinel.raw_decrypted_data_key,
            algorithm=ALGORITHM
        )
        mock_master_key._key_check.assert_called_once_with(sentinel.encrypted_data_key)
        mock_master_key._decrypt_data_key.assert_called_once_with(
            encrypted_data_key=sentinel.encrypted_data_key,
            algorithm=ALGORITHM,
            encryption_context=VALUES['encryption_context']
        )
