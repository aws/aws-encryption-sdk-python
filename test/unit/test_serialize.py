"""Unit test suite for aws_encryption_sdk.internal.formatting.serialize"""
import unittest

from mock import MagicMock, patch
import six

from aws_encryption_sdk.exceptions import SerializationError
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.identifiers import ContentAADString
from aws_encryption_sdk.internal.structures import EncryptedData
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo
from .test_values import VALUES


class TestSerialize(unittest.TestCase):

    def setUp(self):
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.encryption_algorithm.block_size = VALUES['block_size']
        self.mock_algorithm.algorithm_id = VALUES['algorithm_id']
        self.mock_algorithm.iv_len = VALUES['iv_len']
        self.mock_algorithm.tag_len = self.mock_algorithm.auth_len = VALUES['tag_len']

        self.mock_key_provider = MasterKeyInfo(
            provider_id=VALUES['provider_id'],
            key_info=VALUES['key_info']
        )
        self.mock_wrapping_algorithm = MagicMock()
        self.mock_wrapping_algorithm.algorithm = self.mock_algorithm
        # Set up encryption_context patch
        self.mock_serialize_acc_patcher = patch(
            'aws_encryption_sdk.internal.formatting.serialize.aws_encryption_sdk.internal.formatting.encryption_context'
        )
        self.mock_serialize_acc = self.mock_serialize_acc_patcher.start()
        self.mock_serialize_acc.serialize_encryption_context.return_value = VALUES['serialized_encryption_context']
        # Set up crypto patch
        self.mock_crypto_patcher = patch(
            'aws_encryption_sdk.internal.formatting.serialize.aws_encryption_sdk.internal.crypto'
        )
        self.mock_crypto = self.mock_crypto_patcher.start()
        # Set up validate_frame_length patch
        self.mock_valid_frame_length_patcher = patch(
            'aws_encryption_sdk.internal.formatting.serialize.aws_encryption_sdk.internal.utils.validate_frame_length'
        )
        self.mock_valid_frame_length = self.mock_valid_frame_length_patcher.start()
        # Set up mock signer
        self.mock_signer = MagicMock()
        self.mock_signer.update.return_value = None
        self.mock_signer.finalize.return_value = VALUES['signature']

    def tearDown(self):
        self.mock_serialize_acc_patcher.stop()
        self.mock_crypto_patcher.stop()
        self.mock_valid_frame_length_patcher.stop()

    def test_serialize_header(self):
        """Validate that the _serialize_header function
            behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=VALUES['deserialized_header_small_frame'],
            signer=self.mock_signer
        )
        self.mock_serialize_acc.serialize_encryption_context.assert_called_once_with(
            VALUES['updated_encryption_context']
        )
        self.mock_signer.update.assert_called_once_with(VALUES['serialized_header_small_frame'])
        assert test == VALUES['serialized_header_small_frame']

    def test_serialize_header_no_signer(self):
        """Validate that the _serialize_header function
            behaves as expected when called with no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=VALUES['deserialized_header_small_frame']
        )

    def test_serialize_header_auth(self):
        """Validate that the _create_header_auth function
            behaves as expected.
        """
        self.mock_crypto.encrypt.return_value = VALUES['header_auth_base']
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            algorithm=self.mock_algorithm,
            header=VALUES['serialized_header'],
            message_id=VALUES['message_id'],
            encryption_data_key=VALUES['data_key_obj'],
            signer=self.mock_signer
        )
        self.mock_crypto.encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=VALUES['data_key'],
            plaintext=b'',
            associated_data=VALUES['serialized_header'],
            message_id=VALUES['message_id']
        )
        self.mock_signer.update.assert_called_once_with(VALUES['serialized_header_auth'])
        assert test == VALUES['serialized_header_auth']

    def test_serialize_header_auth_no_signer(self):
        """Validate that the _create_header_auth function
            behaves as expected when called with no signer.
        """
        self.mock_crypto.encrypt.return_value = VALUES['header_auth_base']
        aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            algorithm=self.mock_algorithm,
            header=VALUES['serialized_header'],
            message_id=VALUES['message_id'],
            encryption_data_key=VALUES['data_key_obj']
        )

    def test_serialize_single_block_open(self):
        """Validate that the serialize_single_block_open
            function behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_single_block_open(
            algorithm=self.mock_algorithm,
            iv=VALUES['final_frame_base'].iv,
            plaintext_length=len(VALUES['data_128']),
            signer=self.mock_signer
        )
        self.mock_signer.update.assert_called_once_with(VALUES['serialized_single_block_start'])
        assert test == VALUES['serialized_single_block_start']

    def test_serialize_single_block_open_no_signer(self):
        """Validate that the serialize_single_block_open
            function behaves as expected when called with
            no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_single_block_open(
            algorithm=self.mock_algorithm,
            iv=VALUES['final_frame_base'].iv,
            plaintext_length=len(VALUES['data_128'])
        )

    def test_serialize_single_block_close(self):
        """Validate that the serialize_single_block_close
            function behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_single_block_close(
            tag=VALUES['final_frame_base'].tag,
            signer=self.mock_signer
        )
        self.mock_signer.update.assert_called_once_with(VALUES['serialized_single_block_close'])
        assert test == VALUES['serialized_single_block_close']

    def test_serialize_single_block_close_no_signer(self):
        """Validate that the serialize_single_block_close
            function behaves as expected when called with
            no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_single_block_close(
            tag=VALUES['final_frame_base'].tag
        )

    def test_encrypt_and_serialize_frame(self):
        """Validate that the _encrypt_and_serialize_frame
            function behaves as expected for a normal frame.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES['frame_aac']
        self.mock_crypto.encrypt.return_value = VALUES['frame_base']
        source_plaintext = VALUES['data_128'] * 2
        test_serialized, test_remainder = aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=source_plaintext,
            message_id=VALUES['message_id'],
            encryption_data_key=VALUES['data_key_obj'],
            frame_length=VALUES['small_frame_length'],
            sequence_number=1,
            is_final_frame=False,
            signer=self.mock_signer
        )
        self.mock_serialize_acc.assemble_content_aad.assert_called_once_with(
            message_id=VALUES['message_id'],
            aad_content_string=ContentAADString.FRAME_STRING_ID,
            seq_num=1,
            length=VALUES['small_frame_length']
        )
        self.mock_crypto.encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=VALUES['data_key'],
            plaintext=source_plaintext[:VALUES['small_frame_length']],
            associated_data=VALUES['frame_aac'],
            message_id=VALUES['message_id']
        )
        self.mock_signer.update.assert_called_once_with(VALUES['serialized_frame'])
        assert test_serialized == VALUES['serialized_frame']
        assert test_remainder == source_plaintext[VALUES['small_frame_length']:]

    def test_encrypt_and_serialize_frame_no_signer(self):
        """Validate that the _encrypt_and_serialize_frame
            function behaves as expected for a normal frame
            when called with no signer.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES['frame_aac']
        self.mock_crypto.encrypt.return_value = VALUES['frame_base']
        aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=VALUES['data_128'] * 2,
            message_id=VALUES['message_id'],
            encryption_data_key=VALUES['data_key_obj'],
            frame_length=len(VALUES['data_128']),
            is_final_frame=False,
            sequence_number=1
        )

    @patch('aws_encryption_sdk.internal.formatting.serialize.aws_encryption_sdk.internal.defaults')
    def test_encrypt_and_serialize_frame_too_many_frames(self, mock_defaults):
        """Validate that the _encrypt_and_serialize_frame
            function behaves as expected for a frame when
            the the sequence number exceeds the maximum.
        """
        mock_defaults.MAX_FRAME_COUNT = 0
        with six.assertRaisesRegex(self, SerializationError, 'Max frame count exceeded'):
            aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
                algorithm=self.mock_algorithm,
                plaintext=VALUES['data_128'] * 2,
                message_id=VALUES['message_id'],
                encryption_data_key=VALUES['data_key_obj'],
                frame_length=len(VALUES['data_128']),
                is_final_frame=False,
                sequence_number=1
            )

    def test_encrypt_and_serialize_frame_final(self):
        """Validate that the _encrypt_and_serialize_frame
            function behaves as expected for a final frame.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES['final_frame_aac']
        self.mock_crypto.encrypt.return_value = VALUES['final_frame_base']
        test_serialized, test_remainder = aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=VALUES['data_128'],
            message_id=VALUES['message_id'],
            encryption_data_key=VALUES['data_key_obj'],
            frame_length=len(VALUES['data_128']),
            sequence_number=1,
            is_final_frame=True,
            signer=self.mock_signer
        )
        self.mock_serialize_acc.assemble_content_aad.assert_called_once_with(
            message_id=VALUES['message_id'],
            aad_content_string=ContentAADString.FINAL_FRAME_STRING_ID,
            seq_num=1,
            length=len(VALUES['data_128'])
        )
        self.mock_crypto.encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=VALUES['data_key'],
            plaintext=VALUES['data_128'],
            associated_data=VALUES['final_frame_aac'],
            message_id=VALUES['message_id']
        )
        self.mock_signer.update.assert_called_once_with(VALUES['serialized_final_frame'])
        assert test_serialized == VALUES['serialized_final_frame']
        assert test_remainder == b''

    def test_encrypt_and_serialize_frame_final_no_signer(self):
        """Validate that the _encrypt_and_serialize_frame
            function behaves as expected for a final frame
            when called with no signer.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES['final_frame_aac']
        self.mock_crypto.encrypt.return_value = VALUES['final_frame_base']
        aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=VALUES['data_128'],
            message_id=VALUES['message_id'],
            encryption_data_key=VALUES['data_key_obj'],
            frame_length=len(VALUES['data_128']),
            is_final_frame=True,
            sequence_number=1
        )

    def test_serialize_footer_with_signer(self):
        """Validate that the serialize_footer function behaves as expected
            when called with a signer.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_footer(self.mock_signer)
        self.mock_signer.finalize.assert_called_with()
        assert test == VALUES['serialized_footer']

    def test_serialize_footer_no_signer(self):
        """Validate that the serialize_footer function behaves as expected
            when called without a signer.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_footer(None)
        assert test == b''

    def test_serialize_wrapped_key_asymmetric(self):
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.mock_key_provider,
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
            encrypted_wrapped_key=EncryptedData(
                iv=None,
                ciphertext=VALUES['data_128'],
                tag=None
            )
        )
        assert test == EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id=VALUES['provider_id'],
                key_info=VALUES['wrapped_keys']['raw']['key_info']
            ),
            encrypted_data_key=VALUES['data_128']
        )

    def test_serialize_wrapped_key_symmetric(self):
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.mock_key_provider,
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
            encrypted_wrapped_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data']
        )
        assert test == EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id=VALUES['provider_id'],
                key_info=VALUES['wrapped_keys']['serialized']['key_info']
            ),
            encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext']
        )
