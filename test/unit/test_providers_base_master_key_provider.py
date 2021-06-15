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
"""Test suite for aws_encryption_sdk.key_providers.base.MasterKeyProvider"""
import attr
import pytest
from mock import MagicMock, PropertyMock, call, patch, sentinel

from aws_encryption_sdk.exceptions import (
    DecryptKeyError,
    IncorrectMasterKeyError,
    InvalidKeyIdError,
    MasterKeyProviderError,
)
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyProvider, MasterKeyProviderConfig

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@attr.s(hash=True)
class MockMasterKeyProviderConfig(MasterKeyProviderConfig):
    provider_id = attr.ib(hash=True)
    mock_new_master_key = attr.ib(hash=True, default=None)


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


def test_repr():
    test = MockMasterKeyProvider(provider_id="ex_provider_id", mock_new_master_key="ex_new_master_key")

    assert repr(test) == (
        "MockMasterKeyProvider(" "mock_new_master_key=ex_new_master_key, " "provider_id=ex_provider_id" ")"
    )


class TestBaseMasterKeyProvider(object):
    def test_provider_id_enforcement(self):
        class TestProvider(MasterKeyProvider):
            def _new_master_key(self, key_id):
                pass

        with pytest.raises(TypeError) as excinfo:
            TestProvider()
        excinfo.match("Can't instantiate abstract class TestProvider *")

    def test_new_master_key_enforcement(self):
        class TestProvider(MasterKeyProvider):
            provider_id = None

        with pytest.raises(TypeError) as excinfo:
            TestProvider()
        excinfo.match("Can't instantiate abstract class TestProvider *")

    def test_master_keys_for_encryption(self):
        mock_master_key_a = MagicMock()
        mock_master_key_a.master_keys_for_encryption.return_value = (
            sentinel.master_key_a,
            (sentinel.master_key_i, sentinel.master_key_a),
        )
        mock_master_key_b = MagicMock()
        mock_master_key_b.master_keys_for_encryption.return_value = (sentinel.master_key_b, (sentinel.master_key_b,))
        mock_key_provider_c = MagicMock()
        mock_key_provider_c.master_keys_for_encryption.return_value = (
            sentinel.master_key_c,
            [sentinel.master_key_c, sentinel.master_key_d, sentinel.master_key_e],
        )
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_master_key_a, mock_master_key_b, mock_key_provider_c]
        test_primary, test = mock_master_key_provider.master_keys_for_encryption(
            encryption_context=sentinel.encryption_context,
            plaintext_rostream=sentinel.plaintext_rostream,
            plaintext_length=sentinel.plaintext_length,
        )
        mock_master_key_a.master_keys_for_encryption.assert_called_once_with(
            sentinel.encryption_context, sentinel.plaintext_rostream, sentinel.plaintext_length
        )
        mock_master_key_b.master_keys_for_encryption.assert_called_once_with(
            sentinel.encryption_context, sentinel.plaintext_rostream, sentinel.plaintext_length
        )
        mock_key_provider_c.master_keys_for_encryption.assert_called_once_with(
            sentinel.encryption_context, sentinel.plaintext_rostream, sentinel.plaintext_length
        )
        assert test_primary is sentinel.master_key_a
        assert test == [
            sentinel.master_key_i,
            sentinel.master_key_a,
            sentinel.master_key_b,
            sentinel.master_key_c,
            sentinel.master_key_d,
            sentinel.master_key_e,
        ]

    def test_master_keys_for_encryption_no_master_keys(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        with pytest.raises(MasterKeyProviderError) as excinfo:
            mock_master_key_provider.master_keys_for_encryption(
                encryption_context=sentinel.encryption_context,
                plaintext_rostream=sentinel.plaintext_rostream,
                plaintext_length=sentinel.plaintext_length,
            )
        excinfo.match("No Master Keys available from Master Key Provider")

    def test_add_master_keys_from_list(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key = MagicMock()
        mock_master_key_provider.add_master_keys_from_list([sentinel.key_a, sentinel.key_b, sentinel.key_c])
        mock_master_key_provider.add_master_key.assert_has_calls(
            (call(sentinel.key_a), call(sentinel.key_b), call(sentinel.key_c))
        )

    def test_add_master_key_new(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._new_master_key.return_value = sentinel.new_master_key
        mock_master_key_provider.add_master_key(VALUES["key_info"])
        mock_master_key_provider._new_master_key.assert_called_once_with(VALUES["key_info"])
        assert sentinel.new_master_key in mock_master_key_provider._members
        assert mock_master_key_provider._encrypt_key_index[VALUES["key_info"]] is sentinel.new_master_key

    def test_add_master_key_exists(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._encrypt_key_index = {VALUES["key_info"]: sentinel.existing_master_key}
        mock_master_key_provider.add_master_key(VALUES["key_info"])
        assert not mock_master_key_provider._new_master_key.called

    def test_add_master_key_to_bytes_exists(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._encrypt_key_index = {b"ex_key_info": sentinel.existing_master_key}
        mock_master_key_provider.add_master_key("ex_key_info")
        assert not mock_master_key_provider._new_master_key.called

    def test_add_master_key_providers_from_list(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key_provider = MagicMock()
        mock_master_key_provider.add_master_key_providers_from_list(
            [sentinel.key_provider_a, sentinel.key_provider_b, sentinel.key_provider_c]
        )
        mock_master_key_provider.add_master_key_provider.assert_has_calls(
            (call(sentinel.key_provider_a), call(sentinel.key_provider_b), call(sentinel.key_provider_c))
        )

    def test_master_key_provider(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key_provider(sentinel.new_key_provider)
        assert sentinel.new_key_provider in mock_master_key_provider._members

    def test_master_key_to_bytes(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key = MagicMock()
        mock_master_key_provider._encrypt_key_index[b"ex_key_info"] = sentinel.new_master_key
        mock_master_key_provider.master_key_for_encrypt("ex_key_info")
        mock_master_key_provider.add_master_key.assert_called_once_with(b"ex_key_info")

    def test_master_key_for_encrypt(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.add_master_key = MagicMock()
        mock_master_key_provider._encrypt_key_index[VALUES["key_info"]] = sentinel.new_master_key
        test = mock_master_key_provider.master_key_for_encrypt(VALUES["key_info"])
        mock_master_key_provider.add_master_key.assert_called_once_with(VALUES["key_info"])
        assert test is sentinel.new_master_key

    def test_master_key_for_decrypt_in_encrypt_key_index(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._encrypt_key_index[sentinel.key_info] = sentinel.known_encrypt_master_key
        mock_master_key_provider._decrypt_key_index[sentinel.key_info] = sentinel.known_decrypt_master_key

        test = mock_master_key_provider.master_key_for_decrypt(sentinel.key_info)

        assert test is sentinel.known_encrypt_master_key
        assert not mock_master_key_provider._new_master_key.called

    def test_master_key_for_decrypt_in_decrypt_key_index(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock()
        mock_master_key_provider._encrypt_key_index = {}
        mock_master_key_provider._decrypt_key_index[sentinel.key_info] = sentinel.known_decrypt_master_key

        test = mock_master_key_provider.master_key_for_decrypt(sentinel.key_info)

        assert test is sentinel.known_decrypt_master_key
        assert not mock_master_key_provider._new_master_key.called

    def test_master_key_for_decrypt(self):
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._new_master_key = MagicMock(return_value=sentinel.new_master_key)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        # //= type=test
        # //# For each encrypted data key in the filtered set, one at a time, the
        # //# master key provider MUST call Get Master Key (aws-kms-mrk-aware-
        # //# master-key-provider.md#get-master-key) with the encrypted data key's
        # //# provider info as the AWS KMS key ARN.
        test = mock_master_key_provider.master_key_for_decrypt(sentinel.key_info)

        mock_master_key_provider._new_master_key.assert_called_once_with(sentinel.key_info)
        assert mock_master_key_provider._decrypt_key_index[sentinel.key_info] is sentinel.new_master_key
        assert test is sentinel.new_master_key

    def test_decrypt_data_key_successful(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.return_value = sentinel.data_key
        mock_member.master_key_for_decrypt.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member]
        test = mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        mock_member.master_key_for_decrypt.assert_called_once_with(sentinel.key_info)
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        # //= type=test
        # //# It MUST call Decrypt Data Key
        # //# (aws-kms-mrk-aware-master-key.md#decrypt-data-key) on this master key
        # //# with the input algorithm, this single encrypted data key, and the
        # //# input encryption context.
        mock_master_key.decrypt_data_key.assert_called_once_with(
            mock_encrypted_data_key, sentinel.algorithm, sentinel.encryption_context
        )
        assert test is sentinel.data_key

    def test_decrypt_data_key_successful_no_key_ids(self):
        """Test that a Master Key Provider configured with vend_masterkey_on_decrypt = True
        without any key ids can successfully decrypt an EDK.
        """
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.return_value = sentinel.data_key

        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info

        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=mock_master_key
        )
        mock_master_key_provider.vend_masterkey_on_decrypt = True
        mock_master_key_provider._members = []
        test = mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        mock_master_key.decrypt_data_key.assert_called_once_with(
            mock_encrypted_data_key, sentinel.algorithm, sentinel.encryption_context
        )
        assert test is sentinel.data_key

    def test_decrypt_data_key_successful_second_try_provider_id(self):
        mock_first_member = MagicMock()
        mock_first_member.provider_id = sentinel.another_provider_id
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.return_value = sentinel.data_key
        mock_member.master_key_for_decrypt.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_first_member, mock_member]
        test = mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        assert not mock_first_member.master_key_for_decrypt.called
        assert test is sentinel.data_key

    def test_decrypt_data_key_successful_multiple_members(self):
        """Test that a Master Key Provider with multiple members which are able
        to decrypt a given EDK will successfully use the first key to decrypt
        and will not try the others.
        """
        mock_member1 = MagicMock()
        mock_member1.provider_id = sentinel.provider_id
        mock_member1.key_id = sentinel.key_info1

        mock_member2 = MagicMock()
        mock_member2.provider_id = sentinel.provider_id
        mock_member2.key_id = sentinel.key_info2

        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.return_value = sentinel.data_key

        mock_member1.master_key_for_decrypt.return_value = mock_master_key

        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info

        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member1, mock_member2]
        test = mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        assert mock_member1.master_key_for_decrypt.called
        assert not mock_member2.master_key_for_decrypt.called
        assert test is sentinel.data_key

    def test_decrypt_data_key_successful_one_matching_member_no_vend(self):
        """Test that a Master Key Provider configured to not vend keys
        can successfully decrypt an EDK when it was configured with a
        key that is able to decrypt the EDK.
        """
        mock_member = MagicMock()
        mock_member.__class__ = MasterKey
        mock_member.provider_id = sentinel.provider_id
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProviderNoVendOnDecrypt(provider_id=sentinel.provider_id)
        mock_master_key_provider._members = [mock_member]
        mock_master_key_provider.master_key_for_decrypt = MagicMock()
        mock_master_key_provider.decrypt_data_key(
            encrypted_data_key=mock_encrypted_data_key,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        mock_member.decrypt_data_key.assert_called_once_with(
            mock_encrypted_data_key, sentinel.algorithm, sentinel.encryption_context
        )

    def test_decrypt_data_key_unsuccessful_no_matching_members(self):
        """Test that a Master Key Provider returns the correct error when none
        of its members are able to successfully decrypt an EDK
        """
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.another_provider_id
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = DecryptKeyError()
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=mock_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt data key")

    def test_decrypt_data_key_unsuccessful_matching_provider_invalid_key_id(self):
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info

        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.master_key
        )
        with patch.object(
            mock_master_key_provider, "master_key_for_decrypt", new_callable=PropertyMock, side_effect=InvalidKeyIdError
        ) as mock_master_key:
            with pytest.raises(DecryptKeyError) as excinfo:
                mock_master_key_provider.decrypt_data_key(
                    encrypted_data_key=mock_encrypted_data_key,
                    algorithm=sentinel.algorithm,
                    encryption_context=sentinel.encryption_context,
                )
            excinfo.match("Unable to decrypt data key")
            mock_master_key.assert_called_once_with(sentinel.key_info)

    def test_decrypt_data_key_unsuccessful_no_matching_members_no_vend(self):
        """Test that a Master Key Provider cannot decrypt an EDK when it is
        configured to not vend keys and no keys explicitly configured
        match the EDK.
        """
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.another_provider_id
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProviderNoVendOnDecrypt(provider_id=sentinel.provider_id)
        mock_master_key_provider._members = [mock_member]
        mock_master_key_provider.master_key_for_decrypt = MagicMock()
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt data key")
        assert not mock_master_key_provider.master_key_for_decrypt.called

    def test_decrypt_data_key_unsuccessful_invalid_key_info(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_member.master_key_for_decrypt.side_effect = (InvalidKeyIdError,)
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt data key")

    def test_decrypt_data_key_unsuccessful_incorrect_master_key(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = (IncorrectMasterKeyError,)
        mock_member.master_key_for_decrypt.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id_2, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt data key")

    def test_decrypt_data_key_unsuccessful_master_key_decrypt_error(self):
        mock_member = MagicMock()
        mock_member.provider_id = sentinel.provider_id
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = (DecryptKeyError,)
        mock_member.master_key_for_decrypt.return_value = mock_master_key
        mock_encrypted_data_key = MagicMock()
        mock_encrypted_data_key.key_provider.provider_id = sentinel.provider_id
        mock_encrypted_data_key.key_provider.key_info = sentinel.key_info
        mock_master_key = MagicMock()
        mock_master_key.decrypt_data_key.side_effect = DecryptKeyError()
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=mock_master_key
        )
        mock_master_key_provider._members = [mock_member]
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=mock_encrypted_data_key,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt data key")

    def test_decrypt_data_key_unsuccessful_no_members(self):
        """Test that a Master Key Provider configured with no master keys fails
        to decrypt an EDK.
        """
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider._members = []
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key(
                encrypted_data_key=MagicMock(),
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt data key")

    def test_decrypt_data_key_from_list_first_try(self):
        """Test that a Master Key Provider configured with a single master key is able
        to decrypt from a list of EDKs where the first EDK is decryptable by the
        master key.
        """
        mock_decrypt_data_key = MagicMock()
        mock_decrypt_data_key.return_value = sentinel.data_key
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.decrypt_data_key = mock_decrypt_data_key
        test = mock_master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=[sentinel.encrypted_data_key_a, sentinel.encrypted_data_key_b],
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        # //= type=test
        # //# If the decrypt data key call is
        # //# successful, then this function MUST return this result and not
        # //# attempt to decrypt any more encrypted data keys.
        mock_decrypt_data_key.assert_called_once_with(
            sentinel.encrypted_data_key_a, sentinel.algorithm, sentinel.encryption_context
        )
        assert test is sentinel.data_key

    def test_decrypt_data_key_from_list_second_try(self):
        """Test that a Master Key Provider configured with a single master key is able
        to decrypt from a list of EDKs where the first EDK is not decryptable by the
        master key but the second is.
        """
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.decrypt_data_key = MagicMock()
        mock_master_key_provider.decrypt_data_key.side_effect = (DecryptKeyError, sentinel.data_key)
        test = mock_master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=[sentinel.encrypted_data_key_a, sentinel.encrypted_data_key_b],
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        mock_master_key_provider.decrypt_data_key.assert_has_calls(
            calls=(
                call(sentinel.encrypted_data_key_a, sentinel.algorithm, sentinel.encryption_context),
                call(sentinel.encrypted_data_key_b, sentinel.algorithm, sentinel.encryption_context),
            ),
            any_order=False,
        )
        assert test is sentinel.data_key

    def test_decrypt_data_key_from_list_unsuccessful(self):
        """Test that a Master Key Provider configured with a single master key fails
        to decrypt from a list of EDKs when each EDK throws an exception.
        """
        mock_master_key_provider = MockMasterKeyProvider(
            provider_id=sentinel.provider_id, mock_new_master_key=sentinel.new_master_key
        )
        mock_master_key_provider.decrypt_data_key = MagicMock()
        mock_master_key_provider.decrypt_data_key.side_effect = (DecryptKeyError, DecryptKeyError)
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
        # //= type=test
        # //# If all the input encrypted data keys have been processed then this
        # //# function MUST yield an error that includes all the collected errors.
        # Note that Python does not collect errors
        with pytest.raises(DecryptKeyError) as excinfo:
            mock_master_key_provider.decrypt_data_key_from_list(
                encrypted_data_keys=[sentinel.encrypted_data_key_a, sentinel.encrypted_data_key_b],
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
            )
        excinfo.match("Unable to decrypt any data key")
