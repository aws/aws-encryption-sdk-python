"""Test suite for aws_encryption_sdk.key_providers.base.MasterKeyProvider"""
import unittest

import attr
from mock import MagicMock, sentinel, call, PropertyMock, patch
import six

from aws_encryption_sdk.exceptions import (
    DecryptKeyError, InvalidKeyIdError, IncorrectMasterKeyError, MasterKeyProviderError
)
from aws_encryption_sdk.key_providers.base import MasterKeyProvider, MasterKeyProviderConfig


@attr.s
class MockMasterKeyProviderConfig(MasterKeyProviderConfig):
    provider_id = attr.ib()
    mock_new_master_key = attr.ib(default=None)


class MockMasterKeyProvider(MasterKeyProvider):
    provider_id = None
    _config_class = MockMasterKeyProviderConfig

    def __init__(self, **kwargs):
        self.provider_id = self.config.provider_id

    def _new_master_key(self, key_id):
        return self.config.mock_new_master_key


class MockMasterKeyProviderNoVendOnDecrypt(MockMasterKeyProvider):
    vend_masterkey_on_decrypt = False

    def _new_master_key(self, key_id):
        pass


class TestBaseMasterKeyProvider(unittest.TestCase):

    def test_provider_id_enforcement(self):
        class TestProvider(MasterKeyProvider):
            def _new_master_key(self, key_id):
                pass
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestProvider *"
        ):
            TestProvider()

    def test_new_master_key_enforcement(self):
        class TestProvider(MasterKeyProvider):
            provider_id = None
        with six.assertRaisesRegex(
            self,
            TypeError,
            "Can't instantiate abstract class TestProvider *"
        ):
            TestProvider()

    def test_master_keys_for_encryption(self):
        mock_master_key_a = MagicMock()
        mock_master_key_a.master_keys_for_encryption.return_value = (
            sentinel.master_key_a,
            (sentinel.master_key_i, sentinel.master_key_a)
        )
        mock_master_key_b = MagicMock()
        mock_master_key_b.master_keys_for_encryption.return_value = (sentinel.master_key_b, (sentinel.master_key_b,))
        mock_key_provider_c = MagicMock()
        mock_key_provider_c.master_keys_for_encryption.return_value = (
            sentinel.master_key_c,
            [
                sentinel.master_key_c,
                sentinel.master_key_d,
                sentinel.master_key_e
            ]
        )
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [
            mock_master_key_a,
            mock_master_key_b,
            mock_key_provider_c
        ]
        test_primary, test = mock_master_key_provider.master_keys_for_encryption(
            encryption_context=sentinel.encryption_context,
            plaintext_rostream=sentinel.plaintext_rostream,
            plaintext_length=sentinel.plaintext_length
        )
        mock_master_key_a.master_keys_for_encryption.assert_called_once_with(
            sentinel.encryption_context,
            sentinel.plaintext_rostream,
            sentinel.plaintext_length
        )
        mock_master_key_b.master_keys_for_encryption.assert_called_once_with(
            sentinel.encryption_context,
            sentinel.plaintext_rostream,
            sentinel.plaintext_length
        )
        mock_key_provider_c.master_keys_for_encryption.assert_called_once_with(
            sentinel.encryption_context,
            sentinel.plaintext_rostream,
            sentinel.plaintext_length
        )
        assert test_primary is sentinel.master_key_a
        assert test == [
            sentinel.master_key_i,
            sentinel.master_key_a,
            sentinel.master_key_b,
            sentinel.master_key_c,
            sentinel.master_key_d,
            sentinel.master_key_e
        ]

    def test_master_keys_for_encryption_no_master_keys(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        with six.assertRaisesRegex(self, MasterKeyProviderError, 'No Master Keys available from Master Key Provider'):
            mock_master_key_provider.master_keys_for_encryption(
                encryption_context=sentinel.encryption_context,
                plaintext_rostream=sentinel.plaintext_rostream,
                plaintext_length=sentinel.plaintext_length
            )

    def test_add_master_keys_from_list(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key = MagicMock()
        mock_master_key_provider.add_master_keys_from_list([
            sentinel.key_a,
            sentinel.key_b,
            sentinel.key_c
        ])
        mock_master_key_provider.add_master_key.assert_has_calls((
            call(sentinel.key_a),
            call(sentinel.key_b),
            call(sentinel.key_c)
        ))

    def test_add_master_key_new(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._new_master_key.return_value = sentinel.new_master_key
        mock_master_key_provider.add_master_key('ex_key_id')
        mock_master_key_provider._new_master_key.assert_called_once_with('ex_key_id')
        assert sentinel.new_master_key in mock_master_key_provider._members
        assert mock_master_key_provider._key_index['ex_key_id'] is sentinel.new_master_key

    def test_add_master_key_exists(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._key_index = {'ex_key_id': sentinel.existing_master_key}
        mock_master_key_provider.add_master_key('ex_key_id')
        assert not mock_master_key_provider._new_master_key.called

    def test_add_master_key_providers_from_list(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key_provider = MagicMock()
        mock_master_key_provider.add_master_key_providers_from_list([
            sentinel.key_provider_a,
            sentinel.key_provider_b,
            sentinel.key_provider_c
        ])
        mock_master_key_provider.add_master_key_provider.assert_has_calls((
            call(sentinel.key_provider_a),
            call(sentinel.key_provider_b),
            call(sentinel.key_provider_c)
        ))

    def test_add_master_key_provider(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key_provider(sentinel.new_key_provider)
        assert sentinel.new_key_provider in mock_master_key_provider._members

    def test_master_key(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key = MagicMock()
        mock_master_key_provider._key_index['ex_key_id'] = sentinel.new_master_key
        test = mock_master_key_provider.master_key('ex_key_id')
        mock_master_key_provider.add_master_key.assert_called_once_with('ex_key_id')
        assert test is sentinel.new_master_key

    def test_decrypt_data_key_successful(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.return_value = sentinel.data_key
        mock_member.master_key.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member]
        test = mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context
        )
        mock_member.master_key.assert_called_once_with(sentinel.key_info)
        mock_master_key.decrypt_data_key.assert_called_once_with(
            mock_encrypted_data_key,
            sentinel.algorithm,
            sentinel.encryption_context
        )
        assert test is sentinel.data_key

    def test_decrypt_data_key_successful_second_try_provider_id(self):
        mock_first_member = MagicMock()
        mock_first_member.provider_id = sentinel.another_provider_id
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.return_value = sentinel.data_key
        mock_member.master_key.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_first_member, mock_member]
        test = mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context
        )
        assert not mock_first_member.master_key.called
        assert test is sentinel.data_key

    def test_decrypt_data_key_unsuccessful_no_matching_members(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.another_provider_id
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = DecryptKeyError()
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=mock_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )

    def test_decrypt_data_key_unsuccessful_matching_provider_invalid_key_id(self):
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info

        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.master_key
        )
        with patch.object(
            mock_master_key_provider,
            'master_key',
            new_callable=PropertyMock,
            side_effect=InvalidKeyIdError
        ) as mock_master_key:
            with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
                mock_master_key_provider.decrypt_data_key(
                    encrypted_data_key=mock_encrypted_data_key,
                    algorithm=sentinel.algorithm,
                    encryption_context=sentinel.encryption_context
                )
            mock_master_key.assert_called_once_with(sentinel.key_info)

    def test_decrypt_data_key_unsuccessful_no_matching_members_no_vend(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.another_provider_id
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProviderNoVendOnDecrypt(provider_id=sentinel.provider_id)
        mock_master_key_provider._members = [mock_member]
        mock_master_key_provider.master_key = MagicMock()
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )
        assert not mock_master_key_provider.master_key.called

    def test_decrypt_data_key_unsuccessful_invalid_key_info(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_member.master_key.side_effect = (InvalidKeyIdError,)
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )

    def test_decrypt_data_key_unsuccessful_incorrect_master_key(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = (IncorrectMasterKeyError,)
        mock_member.master_key.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )

    def test_decrypt_data_key_unsuccessful_master_key_decryt_error(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = (DecryptKeyError,)
        mock_member.master_key.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = DecryptKeyError()
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=mock_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )

    def test_decrypt_data_key_unsuccessful_no_members(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = []
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt data key'):
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=MagicMock(),
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )

    def test_decrypt_data_key_from_list_first_try(self):
        mock_decrypt_data_key = MagicMock()
        mock_decrypt_data_key.return_value = sentinel.data_key
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.decrypt_data_key = mock_decrypt_data_key
        test = mock_master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=[sentinel.encrypted_data_key_a, sentinel.encrypted_data_key_b],
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context
        )
        mock_decrypt_data_key.assert_called_once_with(
            sentinel.encrypted_data_key_a,
            sentinel.algorithm,
            sentinel.encryption_context)
        assert test is sentinel.data_key

    def test_decrypt_data_key_from_list_second_try(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.decrypt_data_key = MagicMock()
        mock_master_key_provider.decrypt_data_key.side_effect = (DecryptKeyError, sentinel.data_key)
        test = mock_master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=[sentinel.encrypted_data_key_a, sentinel.encrypted_data_key_b],
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context
        )
        mock_master_key_provider.decrypt_data_key.assert_has_calls(
            calls=(
                call(sentinel.encrypted_data_key_a, sentinel.algorithm, sentinel.encryption_context),
                call(sentinel.encrypted_data_key_b, sentinel.algorithm, sentinel.encryption_context)
            ),
            any_order=False
        )
        assert test is sentinel.data_key

    def test_decrypt_data_key_from_list_unsuccessful(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id,
            mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.decrypt_data_key = MagicMock()
        mock_master_key_provider.decrypt_data_key.side_effect = (DecryptKeyError, DecryptKeyError)
        with six.assertRaisesRegex(self, DecryptKeyError, 'Unable to decrypt any data key'):
            mock_master_key_provider.decrypt_data_key_from_list(
                encrypted_data_keys=[sentinel.encrypted_data_key_a, sentinel.encrypted_data_key_b],
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context
            )
