"""
    Test suite for aws_encryption_sdk.internal.utils
"""
import unittest

from mock import MagicMock, patch, sentinel
import six

from aws_encryption_sdk.exceptions import (
    ActionNotAllowedError, NotSupportedError, SerializationError,
    UnknownIdentityError, InvalidDataKeyError, MasterKeyProviderError
)
import aws_encryption_sdk.internal.defaults
import aws_encryption_sdk.identifiers
import aws_encryption_sdk.internal.utils
from aws_encryption_sdk.structures import RawDataKey, DataKey, EncryptedDataKey, MasterKeyInfo
from .test_values import VALUES


class TestUtils(unittest.TestCase):

    def setUp(self):
        # Set up mock key provider and keys
        self.mock_key_provider_1 = MasterKeyInfo(
            provider_id='adijoasijfoi',
            key_info=b'asoiwef8q34'
        )
        self.mock_raw_data_key_1_bytes = b'asioufhaw9eruhtg'
        self.mock_generated_data_key_1_bytes = b'df2hj9348r9824'
        self.mock_encrypted_data_key_1_bytes = b'asioufhaw9eruhtg'
        self.mock_raw_data_key_1 = RawDataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_raw_data_key_1_bytes
        )
        self.mock_generated_data_key_1 = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_generated_data_key_1_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes
        )
        self.mock_encrypted_data_key_1 = EncryptedDataKey(
            key_provider=self.mock_key_provider_1,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes
        )
        self.mock_key_provider_2 = MasterKeyInfo(
            provider_id='9heui5349gh38',
            key_info=b'fj98349yhsfd'
        )
        self.mock_raw_data_key_2_bytes = b'ane4856ht9w87y5'
        self.mock_generated_data_key_2_bytes = b'fih94587ty3t58yh5tg'
        self.mock_encrypted_data_key_2_bytes = b'ane4856ht9w87y5'
        self.mock_generated_data_key_2 = DataKey(
            key_provider=self.mock_key_provider_2,
            data_key=self.mock_generated_data_key_2_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_2_bytes
        )
        self.mock_encrypted_data_key_2 = EncryptedDataKey(
            key_provider=self.mock_key_provider_2,
            encrypted_data_key=self.mock_encrypted_data_key_2_bytes
        )
        self.mock_key_provider_3 = MasterKeyInfo(
            provider_id='sdfiwehjf9384u',
            key_info=b'evih5874yh587tyhu5'
        )
        self.mock_raw_data_key_3_bytes = b'f839u459t83uh5rugh'
        self.mock_generated_data_key_3_bytes = b'sjhfuiehw498gfyu34098upoi'
        self.mock_encrypted_data_key_3_bytes = b'f839u459t83uh5rugh'
        self.mock_generated_data_key_3 = DataKey(
            key_provider=self.mock_key_provider_3,
            data_key=self.mock_generated_data_key_3_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_3_bytes
        )
        self.mock_encrypted_data_key_3 = EncryptedDataKey(
            key_provider=self.mock_key_provider_3,
            encrypted_data_key=self.mock_encrypted_data_key_3_bytes
        )
        self.mock_master_key_provider = MagicMock()
        self.mock_master_key_1 = MagicMock()
        self.mock_master_key_1.encrypt_data_key.return_value = self.mock_encrypted_data_key_1
        self.mock_master_key_1.generate_data_key.return_value = self.mock_generated_data_key_1
        self.mock_master_key_2 = MagicMock()
        self.mock_master_key_2.encrypt_data_key.return_value = self.mock_encrypted_data_key_2
        self.mock_master_key_2.generate_data_key.return_value = self.mock_generated_data_key_2
        self.mock_master_key_3 = MagicMock()
        self.mock_master_key_3.encrypt_data_key.return_value = self.mock_encrypted_data_key_3
        self.mock_master_key_3.generate_data_key.return_value = self.mock_generated_data_key_3
        self.mock_master_key_provider.master_keys_for_encryption.return_value = (
            self.mock_master_key_1,
            [
                self.mock_master_key_1,
                self.mock_master_key_2,
                self.mock_master_key_3
            ]
        )
        self.mock_decrypted_data_key_bytes = b'sehf98w34y987y9uierfh'
        self.mock_encrypted_data_key_bytes = b'sdhf4w398hfwea98ihfr0w8'
        self.mock_data_key = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_decrypted_data_key_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_bytes
        )
        self.mock_encrypted_data_key = EncryptedDataKey(
            key_provider=self.mock_key_provider_1,
            encrypted_data_key=self.mock_encrypted_data_key_bytes
        )
        self.mock_decrypted_data_key = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_decrypted_data_key_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes
        )
        self.mock_master_key_provider.decrypt_data_key.return_value = self.mock_decrypted_data_key
        # Set up mock algorithm
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.encryption_algorithm.block_size = VALUES['block_size']
        self.mock_algorithm.algorithm_id = VALUES['algorithm_id']
        self.mock_algorithm.iv_len = VALUES['iv_len']
        self.mock_algorithm.tag_len = self.mock_algorithm.auth_len = VALUES['tag_len']
        self.mock_algorithm.data_key_len = VALUES['data_key_len']
        # Set up mock objects
        self.mock_bad_encrypted_key = MagicMock()
        self.mock_bad_encrypted_key.encrypted_data_key = sentinel.bad_encrypted_data_key
        self.mock_aws_encryption_sdk = MagicMock()
        # Set up os.urandom patch
        self.mock_urandom_patcher = patch('aws_encryption_sdk.internal.utils.os.urandom')
        self.mock_urandom = self.mock_urandom_patcher.start()
        self.mock_urandom.return_value = sentinel.random
        # Set up KMSClient patch
        self.mock_aws_encryption_sdk_instance = MagicMock()
        self.mock_aws_encryption_sdk_instance.generate_data_key.return_value = (
            VALUES['data_key'],
            VALUES['encrypted_data_key']
        )
        self.mock_aws_encryption_sdk_instance.decrypt.return_value = VALUES['data_key']
        self.mock_aws_encryption_sdk_instance.encrypt.return_value = VALUES['encrypted_data_key']

    def tearDown(self):
        self.mock_urandom_patcher.stop()

    def test_validate_frame_length_negative_frame_length(self):
        """Validate that the validate_frame_length function
            behaves as expected when supplied with a
            negative frame length.
        """
        with six.assertRaisesRegex(
            self,
            SerializationError,
            'Frame size must be a non-negative multiple of the block size of the crypto algorithm: *'
        ):
            aws_encryption_sdk.internal.utils.validate_frame_length(
                frame_length=-1,
                algorithm=self.mock_algorithm
            )

    def test_validate_frame_length_invalid_frame_length(self):
        """Validate that the validate_frame_length function
            behaves as expected when supplied with an
            invalid frame length.
        """
        with six.assertRaisesRegex(
            self,
            SerializationError,
            'Frame size must be a non-negative multiple of the block size of the crypto algorithm: *'
        ):
            aws_encryption_sdk.internal.utils.validate_frame_length(
                frame_length=1,
                algorithm=self.mock_algorithm
            )

    def test_validate_frame_length_too_large(self):
        """Validate that the validate_frame_length function
            behaves as expected when supplied with a
            frame length which is too large.
        """
        with six.assertRaisesRegex(self, SerializationError, 'Frame size too large: *'):
            aws_encryption_sdk.internal.utils.validate_frame_length(
                frame_length=aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE + 1,
                algorithm=self.mock_algorithm
            )

    def test_message_id(self):
        """Validate that the message_id function behaves as expected."""
        test = aws_encryption_sdk.internal.utils.message_id()
        self.mock_urandom.assert_called_once_with(
            aws_encryption_sdk.internal.defaults.MESSAGE_ID_LENGTH
        )
        self.assertEqual(test, sentinel.random)

    def test_get_aad_content_string_no_framing(self):
        """Validate that the get_aad_content_string function behaves
            as expected when called with NO_FRAMING.
        """
        test = aws_encryption_sdk.internal.utils.get_aad_content_string(
            aws_encryption_sdk.identifiers.ContentType.NO_FRAMING,
            False
        )
        assert test == aws_encryption_sdk.identifiers.ContentAADString.SINGLE_BLOCK_STRING_ID

    def test_get_aad_content_string_framing(self):
        """Validate that the get_aad_content_string function behaves
            as expected when called with FRAMED_DATA.
        """
        test = aws_encryption_sdk.internal.utils.get_aad_content_string(
            aws_encryption_sdk.identifiers.ContentType.FRAMED_DATA,
            False
        )
        assert test == aws_encryption_sdk.identifiers.ContentAADString.FRAME_STRING_ID

    def test_get_aad_content_string_framing_final_frame(self):
        """Validate that the get_aad_content_string function behaves as
            expected when called with FRAMED_DATA and final frame.
        """
        test = aws_encryption_sdk.internal.utils.get_aad_content_string(
            aws_encryption_sdk.identifiers.ContentType.FRAMED_DATA,
            True
        )
        assert test == aws_encryption_sdk.identifiers.ContentAADString.FINAL_FRAME_STRING_ID

    def test_get_aad_content_string_framing_bad_type(self):
        """Validate that the get_aad_content_string function behaves as
            expected when called with an unknown content type.
        """
        with six.assertRaisesRegex(self, UnknownIdentityError, 'Unhandled content type'):
            aws_encryption_sdk.internal.utils.get_aad_content_string(-1, False)

    def test_prepare_data_keys_no_master_keys(self):
        """"""
        self.mock_master_key_provider.master_keys_for_encryption.return_value = None, []
        with six.assertRaisesRegex(self, MasterKeyProviderError, 'No Master Keys available from Master Key Provider'):
            aws_encryption_sdk.internal.utils.prepare_data_keys(
                key_provider=self.mock_master_key_provider,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
                plaintext_rostream=sentinel.plaintext_rostream,
                plaintext_length=sentinel.plaintext_length,
                data_key=self.mock_raw_data_key_1
            )

    def test_prepare_data_keys_primary_master_key_not_in_master_keys(self):
        """"""
        self.mock_master_key_provider.master_keys_for_encryption.return_value = sentinel.primary, [sentinel.non_primary]
        with six.assertRaisesRegex(self, MasterKeyProviderError, 'Primary Master Key not in provided Master Keys'):
            aws_encryption_sdk.internal.utils.prepare_data_keys(
                key_provider=self.mock_master_key_provider,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
                plaintext_rostream=sentinel.plaintext_rostream,
                plaintext_length=sentinel.plaintext_length,
                data_key=self.mock_raw_data_key_1
            )

    def test_prepare_data_keys_raw_data_key(self):
        """Validate that the prepare_data_keys function behaves as
            expected when called with a RawDataKey.
        """
        test_encryption_data_key, _ = aws_encryption_sdk.internal.utils.prepare_data_keys(
            key_provider=self.mock_master_key_provider,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
            plaintext_rostream=sentinel.plaintext_rostream,
            plaintext_length=sentinel.plaintext_length,
            data_key=self.mock_raw_data_key_1
        )
        assert not self.mock_master_key_1.generate_data_key.called
        assert test_encryption_data_key == DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_raw_data_key_1_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes
        )

    def test_prepare_data_keys_data_key(self):
        """Validate that the prepare_data_keys function behaves as
            expected when called with a DataKey.
        """
        test_encryption_data_key, test_encrypted_data_keys = aws_encryption_sdk.internal.utils.prepare_data_keys(
            key_provider=self.mock_master_key_provider,
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
            plaintext_rostream=sentinel.plaintext_rostream,
            plaintext_length=sentinel.plaintext_length,
            data_key=self.mock_data_key
        )
        assert self.mock_master_key_1.encrypt_data_key.called
        assert test_encryption_data_key == self.mock_decrypted_data_key
        assert test_encrypted_data_keys == set([
            self.mock_encrypted_data_key_1,
            self.mock_encrypted_data_key_2,
            self.mock_encrypted_data_key_3
        ])

    def test_prepare_data_keys_unsupported_data_key_type(self):
        """Validate that the prepare_data_keys function behaves as
            expected when called with an unsupported data_key type.
        """
        with six.assertRaisesRegex(self, NotSupportedError, 'Unsupported data_key type: *'):
            aws_encryption_sdk.internal.utils.prepare_data_keys(
                key_provider=self.mock_master_key_provider,
                algorithm=sentinel.algorithm,
                encryption_context=sentinel.encryption_context,
                plaintext_rostream=sentinel.plaintext_rostream,
                plaintext_length=sentinel.plaintext_length,
                data_key='THIS IS NOT A VALID DATA KEY'
            )

    @patch('aws_encryption_sdk.internal.utils.to_bytes', return_value=sentinel.bytes)
    @patch('aws_encryption_sdk.internal.utils.io.BytesIO', return_value=sentinel.bytesio)
    def test_prep_stream_data(self, mock_bytesio, mock_to_bytes):
        test = aws_encryption_sdk.internal.utils.prep_stream_data(sentinel.data)
        mock_to_bytes.assert_called_once_with(sentinel.data)
        mock_bytesio.assert_called_once_with(sentinel.bytes)
        assert test is sentinel.bytesio

    def test_source_data_key_length_check_valid(self):
        mock_algorithm = MagicMock()
        mock_algorithm.kdf_input_len = 5
        mock_data_key = MagicMock()
        mock_data_key.data_key = '12345'
        aws_encryption_sdk.internal.utils.source_data_key_length_check(
            source_data_key=mock_data_key,
            algorithm=mock_algorithm
        )

    def test_source_data_key_length_check_invalid(self):
        mock_algorithm = MagicMock()
        mock_algorithm.kdf_input_len = 5
        mock_data_key = MagicMock()
        mock_data_key.data_key = '1234'
        with six.assertRaisesRegex(
            self,
            InvalidDataKeyError,
            'Invalid Source Data Key length 4 for algorithm required: 5'
        ):
            aws_encryption_sdk.internal.utils.source_data_key_length_check(
                source_data_key=mock_data_key,
                algorithm=mock_algorithm
            )

    @patch('aws_encryption_sdk.internal.utils.ROStream._duplicate_api')
    def test_rostream_init(self, mock_duplicate):
        test = aws_encryption_sdk.internal.utils.ROStream(sentinel.source)
        assert test._source_stream is sentinel.source
        mock_duplicate.assert_called_once_with()

    def test_rostream_write(self):
        test = aws_encryption_sdk.internal.utils.ROStream(sentinel.source)
        with six.assertRaisesRegex(self, ActionNotAllowedError, 'Write not allowed on ROStream objects'):
            test.write(None)

    def test_rostream_duplicate_api(self):
        class _TestSource(object):
            z = sentinel.z
            x = sentinel.x
            write = sentinel.write
        source = _TestSource()
        test = aws_encryption_sdk.internal.utils.ROStream(source)
        assert test.z is source.z
        assert test.x is source.x
        assert test.write is not source.write
