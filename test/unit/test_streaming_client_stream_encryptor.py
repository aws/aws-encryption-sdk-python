"""Unit test suite for aws_encryption_sdk.streaming_client.StreamEncryptor"""
import io
import unittest
from mock import MagicMock, patch, sentinel, call
import six
from aws_encryption_sdk.exceptions import NotSupportedError, SerializationError
from aws_encryption_sdk.streaming_client import StreamEncryptor
import aws_encryption_sdk.internal.defaults
from aws_encryption_sdk.internal.crypto.providers.base import MasterKeyProvider, MasterKey
from aws_encryption_sdk.internal.identifiers import Algorithm, ContentType
from aws_encryption_sdk.internal.structures import MessageHeader
from .test_values import VALUES


class TestStreamEncryptor(unittest.TestCase):

    def setUp(self):
        # Create mock key provider
        self.mock_key_provider = MagicMock()
        self.mock_key_provider.__class__ = MasterKeyProvider

        self.mock_master_key = MagicMock()
        self.mock_master_key.__class__ = MasterKey

        self.mock_input_stream = MagicMock()
        self.mock_input_stream.__class__ = io.IOBase

        self.mock_frame_length = MagicMock()
        self.mock_frame_length.__class__ = int

        self.mock_algorithm = MagicMock()
        self.mock_algorithm.__class__ = Algorithm

        self.mock_encrypted_data_keys = MagicMock()
        self.mock_encrypted_data_keys.__class__ = set

        self.plaintext = six.b('''
            Lorem Ipsum is simply dummy text of the printing and typesetting industry.
            Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,
            when an unknown printer took a galley of type and scrambled it to make a type
            specimen book. It has survived not only five centuries, but also the leap into
            electronic typesetting, remaining essentially unchanged. It was popularised in
            the 1960s with the release of Letraset sheets containing Lorem Ipsum passages,
            and more recently with desktop publishing software like Aldus PageMaker including
            versions of Lorem Ipsum.
        ''')
        # Set up content_type patch
        self.mock_content_type_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.utils.content_type'
        )
        self.mock_content_type = self.mock_content_type_patcher.start()
        self.mock_content_type.return_value = sentinel.content_type
        # Set up validate_from_length patch
        self.mock_validate_frame_length_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.utils.validate_frame_length'
        )
        self.mock_validate_frame_length = self.mock_validate_frame_length_patcher.start()
        # Set up message_id patch
        self.mock_message_id_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.utils.message_id'
        )
        self.mock_message_id = self.mock_message_id_patcher.start()
        self.mock_message_id.return_value = VALUES['message_id']
        # Set up signer patch
        self.mock_signer_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.crypto.Signer'
        )
        self.mock_signer = self.mock_signer_patcher.start()
        self.mock_signer_instance = MagicMock()
        self.mock_signer_instance.encoded_public_key.return_value = sentinel.encoded_public_key
        self.mock_signer.return_value = self.mock_signer_instance
        # Set up codecs patch
        self.mock_codecs_patcher = patch('aws_encryption_sdk.streaming_client.codecs')
        self.mock_codecs = self.mock_codecs_patcher.start()
        self.mock_codecs.decode.return_value = sentinel.decoded_bytes
        # Set up prepare_data_keys patch
        self.mock_prepare_data_keys_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.utils.prepare_data_keys'
        )
        self.mock_prepare_data_keys = self.mock_prepare_data_keys_patcher.start()
        self.mock_encryption_data_key = VALUES['data_key_obj']
        self.mock_prepare_data_keys.return_value = (self.mock_encryption_data_key, self.mock_encrypted_data_keys)
        # Set up serialize_header patch
        self.mock_serialize_header_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.serialize.serialize_header'
        )
        self.mock_serialize_header = self.mock_serialize_header_patcher.start()
        # Set up serialize_header_auth patch
        self.mock_serialize_header_auth_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth'
        )
        self.mock_serialize_header_auth = self.mock_serialize_header_auth_patcher.start()
        # Set up get_aad_content_string patch
        self.mock_get_aad_content_string_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.utils.get_aad_content_string'
        )
        self.mock_get_aad_content_string = self.mock_get_aad_content_string_patcher.start()
        self.mock_get_aad_content_string.return_value = sentinel.aad_content_string
        # Set up assemble_content_aad patch
        self.mock_assemble_content_aad_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.encryption_context.assemble_content_aad'
        )
        self.mock_assemble_content_aad = self.mock_assemble_content_aad_patcher.start()
        self.mock_assemble_content_aad.return_value = sentinel.associated_data
        # Set up encryptor patch
        self.mock_encryptor_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.crypto.Encryptor'
        )
        self.mock_encryptor = self.mock_encryptor_patcher.start()
        self.mock_encryptor_instance = MagicMock()
        self.mock_encryptor_instance.iv = sentinel.iv
        self.mock_encryptor.return_value = self.mock_encryptor_instance
        # Set up serialize_single_block_open patch
        self.mock_serialize_single_block_open_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.serialize.serialize_single_block_open'
        )
        self.mock_serialize_single_block_open = self.mock_serialize_single_block_open_patcher.start()
        # Set up serialize_single_block_close patch
        self.mock_serialize_single_block_close_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.serialize.serialize_single_block_close'
        )
        self.mock_serialize_single_block_close = self.mock_serialize_single_block_close_patcher.start()
        # Set up serialize_footer patch
        self.mock_serialize_footer_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.serialize.serialize_footer'
        )
        self.mock_serialize_footer = self.mock_serialize_footer_patcher.start()
        # Set up serialize_frame patch
        self.mock_serialize_frame_patcher = patch(
            'aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.formatting.serialize.serialize_frame'
        )
        self.mock_serialize_frame = self.mock_serialize_frame_patcher.start()

    def tearDown(self):
        self.mock_content_type_patcher.stop()
        self.mock_validate_frame_length_patcher.stop()
        self.mock_message_id_patcher.stop()
        self.mock_signer_patcher.stop()
        self.mock_codecs_patcher.stop()
        self.mock_prepare_data_keys_patcher.stop()
        self.mock_serialize_header_patcher.stop()
        self.mock_serialize_header_auth_patcher.stop()
        self.mock_get_aad_content_string_patcher.stop()
        self.mock_assemble_content_aad_patcher.stop()
        self.mock_encryptor_patcher.stop()
        self.mock_serialize_single_block_open_patcher.stop()
        self.mock_serialize_single_block_close_patcher.stop()
        self.mock_serialize_footer_patcher.stop()
        self.mock_serialize_frame_patcher.stop()

    def test_init(self):
        test_encryptor = StreamEncryptor(
            source=self.mock_input_stream,
            key_provider=self.mock_key_provider,
            frame_length=self.mock_frame_length,
            algorithm=self.mock_algorithm
        )
        assert test_encryptor.sequence_number == 1
        self.mock_content_type.assert_called_once_with(self.mock_frame_length)
        assert test_encryptor.content_type is sentinel.content_type
        self.mock_validate_frame_length.assert_called_once_with(self.mock_frame_length, self.mock_algorithm)

    def test_init_single_block_message_too_large(self):
        with six.assertRaisesRegex(self, SerializationError, 'Source too large for single block message'):
            StreamEncryptor(
                source=self.mock_input_stream,
                key_provider=self.mock_key_provider,
                frame_length=0,
                algorithm=self.mock_algorithm,
                source_length=aws_encryption_sdk.internal.defaults.MAX_SINGLE_BLOCK_SIZE + 1
            )

    @patch('aws_encryption_sdk.internal.utils.ROStream')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._prep_single_block')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._write_header')
    def test_prep_message_framed_message(self, mock_write_header, mock_prep_single_block, mock_rostream):
        mock_rostream.return_value = sentinel.plaintext_rostream
        test_encryptor = StreamEncryptor(
            source=self.mock_input_stream,
            key_provider=self.mock_key_provider,
            frame_length=self.mock_frame_length,
            source_length=5
        )
        test_encryptor.content_type = ContentType.FRAMED_DATA
        test_encryptor._prep_message()
        self.mock_signer.assert_called_once_with(test_encryptor.config.algorithm)
        self.mock_signer_instance.encoded_public_key.assert_called_once_with()
        self.mock_codecs.decode.assert_called_once_with(sentinel.encoded_public_key)
        test_encryption_context = {aws_encryption_sdk.internal.defaults.ENCODED_SIGNER_KEY: sentinel.decoded_bytes}
        mock_rostream.assert_called_once_with(self.mock_input_stream)
        self.mock_prepare_data_keys.assert_called_once_with(
            key_provider=self.mock_key_provider,
            algorithm=test_encryptor.config.algorithm,
            encryption_context=test_encryption_context,
            plaintext_rostream=sentinel.plaintext_rostream,
            plaintext_length=5,
            data_key=test_encryptor.config.data_key
        )
        assert test_encryptor.header == MessageHeader(
            version=aws_encryption_sdk.internal.defaults.VERSION,
            type=aws_encryption_sdk.internal.defaults.TYPE,
            algorithm=test_encryptor.config.algorithm,
            message_id=VALUES['message_id'],
            encryption_context=test_encryption_context,
            encrypted_data_keys=self.mock_encrypted_data_keys,
            content_type=test_encryptor.content_type,
            content_aad_length=0,
            header_iv_length=test_encryptor.config.algorithm.iv_len,
            frame_length=self.mock_frame_length
        )
        mock_write_header.assert_called_once_with()
        assert not mock_prep_single_block.called
        assert test_encryptor._message_prepped

    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._prep_single_block')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._write_header')
    def test_prep_message_single_block_message(self, mock_write_header, mock_prep_single_block):
        test_encryptor = StreamEncryptor(
            source=self.mock_input_stream,
            key_provider=self.mock_key_provider,
            frame_length=self.mock_frame_length
        )
        test_encryptor.content_type = ContentType.NO_FRAMING
        test_encryptor._prep_message()
        mock_prep_single_block.assert_called_once_with()

    def test_prep_message_no_signer(self):
        test_encryptor = StreamEncryptor(
            source=self.mock_input_stream,
            key_provider=self.mock_key_provider,
            frame_length=self.mock_frame_length,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16
        )
        test_encryptor.content_type = ContentType.FRAMED_DATA
        test_encryptor._prep_message()
        assert not self.mock_signer.called
        assert test_encryptor.header.encryption_context == {}

    def test_write_header(self):
        self.mock_serialize_header.return_value = b'12345'
        self.mock_serialize_header_auth.return_value = b'67890'
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            algorithm=aws_encryption_sdk.internal.defaults.ALGORITHM,
            frame_length=self.mock_frame_length
        )
        test_encryptor.content_type = sentinel.content_type
        test_encryptor.header = MagicMock()
        test_encryptor.header.message_id = VALUES['message_id']
        test_encryptor.signer = sentinel.signer
        test_encryptor.output_buffer = b''
        test_encryptor.encryption_data_key = self.mock_encryption_data_key
        test_encryptor._write_header()
        self.mock_serialize_header.assert_called_once_with(
            header=test_encryptor.header,
            signer=test_encryptor.signer
        )
        self.mock_serialize_header_auth.assert_called_once_with(
            algorithm=test_encryptor.config.algorithm,
            header=b'12345',
            message_id=test_encryptor.header.message_id,
            encryption_data_key=test_encryptor.encryption_data_key,
            signer=test_encryptor.signer
        )
        assert test_encryptor.output_buffer == b'1234567890'

    def test_prep_single_block(self):
        self.mock_serialize_single_block_open.return_value = b'1234567890'
        test_encryptor = StreamEncryptor(
            source=self.mock_input_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test_encryptor._prep_single_block()
        self.mock_get_aad_content_string.assert_called_once_with(
            content_type=test_encryptor.content_type,
            is_final_frame=True
        )
        self.mock_assemble_content_aad.assert_called_once_with(
            message_id=test_encryptor.header.message_id,
            aad_content_string=sentinel.aad_content_string,
            seq_num=1,
            length=test_encryptor.stream_length
        )
        self.mock_encryptor.assert_called_once_with(
            algorithm=test_encryptor.config.algorithm,
            key=test_encryptor.encryption_data_key.data_key,
            associated_data=sentinel.associated_data,
            message_id=test_encryptor.header.message_id
        )
        self.mock_serialize_single_block_open.assert_called_once_with(
            algorithm=test_encryptor.config.algorithm,
            iv=sentinel.iv,
            plaintext_length=test_encryptor.stream_length,
            signer=test_encryptor.signer
        )
        assert test_encryptor.output_buffer == b'1234567890'

    def test_read_bytes_to_single_block_body(self):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.encryptor = MagicMock()
        test_encryptor.encryptor.update.return_value = sentinel.ciphertext
        test = test_encryptor._read_bytes_to_single_block_body(5)
        test_encryptor.encryptor.update.assert_called_once_with(self.plaintext[:5])
        test_encryptor.signer.update.assert_called_once_with(sentinel.ciphertext)
        assert not test_encryptor.source_stream.closed
        assert test is sentinel.ciphertext

    def test_read_bytes_to_single_block_body_too_large(self):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.bytes_read = aws_encryption_sdk.internal.defaults.MAX_SINGLE_BLOCK_SIZE
        with six.assertRaisesRegex(self, SerializationError, 'Source too large for single block message'):
            test_encryptor._read_bytes_to_single_block_body(5)

    def test_read_bytes_to_single_block_body_close(self):
        test_encryptor = StreamEncryptor(
            source=self.mock_input_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.encryptor = MagicMock()
        test_encryptor.encryptor.update.return_value = b'123'
        test_encryptor.encryptor.finalize.return_value = b'456'
        test_encryptor.encryptor.tag = sentinel.tag
        self.mock_serialize_single_block_close.return_value = b'789'
        self.mock_serialize_footer.return_value = b'0-='
        test = test_encryptor._read_bytes_to_single_block_body(len(self.plaintext) + 1)
        test_encryptor.signer.update.assert_has_calls(
            calls=(call(b'123'), call(b'456')),
            any_order=False
        )
        assert test_encryptor.source_stream.closed
        test_encryptor.encryptor.finalize.assert_called_once_with()
        self.mock_serialize_single_block_close.assert_called_once_with(
            tag=test_encryptor.encryptor.tag,
            signer=test_encryptor.signer
        )
        self.mock_serialize_footer.assert_called_once_with(test_encryptor.signer)
        assert test == b'1234567890-='

    def test_read_bytes_to_single_block_body_no_signer(self):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16
        )
        test_encryptor.signer = None
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test_encryptor.encryptor = MagicMock()
        test_encryptor.encryptor.update.return_value = b'123'
        test_encryptor.encryptor.finalize.return_value = b'456'
        test_encryptor.encryptor.tag = sentinel.tag
        self.mock_serialize_single_block_close.return_value = b'789'
        self.mock_serialize_footer.return_value = b'0-='
        test_encryptor._read_bytes_to_single_block_body(len(self.plaintext) + 1)
        assert not self.mock_serialize_footer.called

    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_framed_body')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_single_block_body')
    def test_read_bytes_less_than_buffer(self, mock_read_single_block, mock_read_framed):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.output_buffer = b'1234567'
        test_encryptor._read_bytes(5)
        assert not mock_read_single_block.called
        assert not mock_read_framed.called

    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_framed_body')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_single_block_body')
    def test_read_bytes_closed(self, mock_read_single_block, mock_read_framed):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.source_stream.close()
        test_encryptor._read_bytes(5)
        assert not mock_read_single_block.called
        assert not mock_read_framed.called

    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_framed_body')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_single_block_body')
    def test_read_bytes_framed(self, mock_read_single_block, mock_read_framed):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.content_type = ContentType.FRAMED_DATA
        test_encryptor._read_bytes(5)
        assert not mock_read_single_block.called
        mock_read_framed.assert_called_once_with(5)

    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_framed_body')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_single_block_body')
    def test_read_bytes_single_block(self, mock_read_single_block, mock_read_framed):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.content_type = ContentType.NO_FRAMING
        test_encryptor._read_bytes(5)
        assert not mock_read_framed.called
        mock_read_single_block.assert_called_once_with(5)

    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_framed_body')
    @patch('aws_encryption_sdk.streaming_client.StreamEncryptor._read_bytes_to_single_block_body')
    def test_read_bytes_unsupported_type(self, mock_read_single_block, mock_read_framed):
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test_encryptor.content_type = None
        with six.assertRaisesRegex(self, NotSupportedError, 'Unsupported content type'):
            test_encryptor._read_bytes(5)
        assert not mock_read_single_block.called
        assert not mock_read_framed.called

    def test_read_bytes_to_framed_body_single_frame_read(self):
        self.mock_serialize_frame.return_value = (b'1234', b'')
        pt_stream = io.BytesIO(self.plaintext * 2)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            frame_length=128
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test = test_encryptor._read_bytes_to_framed_body(128)
        self.mock_serialize_frame.assert_called_once_with(
            algorithm=test_encryptor.config.algorithm,
            plaintext=self.plaintext[:128],
            message_id=test_encryptor.header.message_id,
            encryption_data_key=test_encryptor.encryption_data_key,
            frame_length=test_encryptor.config.frame_length,
            sequence_number=1,
            is_final_frame=False,
            signer=test_encryptor.signer
        )
        assert not self.mock_serialize_footer.called
        assert not test_encryptor.source_stream.closed
        assert test == b'1234'

    def test_read_bytes_to_framed_body_single_frame_with_final(self):
        self.mock_serialize_frame.side_effect = (
            (b'FIRST', b''),
            (b'FINAL', b'')
        )
        self.mock_serialize_footer.return_value = b'FOOTER'
        pt_stream = io.BytesIO(self.plaintext[:50])
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            frame_length=50
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test = test_encryptor._read_bytes_to_framed_body(51)
        self.mock_serialize_frame.assert_has_calls(
            calls=(
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=self.plaintext[:50],
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=1,
                    is_final_frame=False,
                    signer=test_encryptor.signer
                ),
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=b'',
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=2,
                    is_final_frame=True,
                    signer=test_encryptor.signer
                )
            ),
            any_order=False
        )
        assert test == b'FIRSTFINALFOOTER'

    def test_read_bytes_to_framed_body_multi_frame_read(self):
        frame_length = int(len(self.plaintext) / 4)
        self.mock_serialize_frame.side_effect = (
            (b'123', self.plaintext[frame_length:]),
            (b'456', self.plaintext[frame_length * 2:]),
            (b'789', self.plaintext[frame_length * 3:]),
            (b'0-=', b''),
            (b'FINAL', b'')
        )
        self.mock_serialize_footer.return_value = b'/*-'
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            frame_length=frame_length
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test = test_encryptor._read_bytes_to_framed_body(len(self.plaintext) + 1)
        self.mock_serialize_frame.assert_has_calls(
            calls=[
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=self.plaintext,
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=1,
                    is_final_frame=False,
                    signer=test_encryptor.signer
                ),
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=self.plaintext[frame_length:],
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=2,
                    is_final_frame=False,
                    signer=test_encryptor.signer
                ),
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=self.plaintext[frame_length * 2:],
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=3,
                    is_final_frame=False,
                    signer=test_encryptor.signer
                ),
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=self.plaintext[frame_length * 3:],
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=4,
                    is_final_frame=False,
                    signer=test_encryptor.signer
                ),
                call(
                    algorithm=test_encryptor.config.algorithm,
                    plaintext=b'',
                    message_id=test_encryptor.header.message_id,
                    encryption_data_key=test_encryptor.encryption_data_key,
                    frame_length=test_encryptor.config.frame_length,
                    sequence_number=5,
                    is_final_frame=True,
                    signer=test_encryptor.signer
                )
            ],
            any_order=False
        )
        self.mock_serialize_footer.assert_called_once_with(test_encryptor.signer)
        assert test_encryptor.source_stream.closed
        assert test == b'1234567890-=FINAL/*-'

    def test_read_bytes_to_framed_body_close(self):
        self.mock_serialize_frame.return_value = (b'1234', b'')
        self.mock_serialize_footer.return_value = b'5678'
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            frame_length=len(self.plaintext)
        )
        test_encryptor.signer = MagicMock()
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test_encryptor._read_bytes_to_framed_body(len(self.plaintext) + 1)
        self.mock_serialize_footer.assert_called_once_with(test_encryptor.signer)
        assert test_encryptor.source_stream.closed

    def test_read_bytes_to_framed_body_close_no_signer(self):
        self.mock_serialize_frame.return_value = (b'1234', b'')
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider,
            frame_length=len(self.plaintext),
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16
        )
        test_encryptor.signer = None
        test_encryptor.header = MagicMock()
        test_encryptor.encryption_data_key = MagicMock()
        test_encryptor._read_bytes_to_framed_body(len(self.plaintext) + 1)
        assert not self.mock_serialize_footer.called
        assert test_encryptor.source_stream.closed

    @patch('aws_encryption_sdk.streaming_client._EncryptionStream.close')
    def test_close(self, mock_close):
        self.mock_encryption_data_key.key_provider = VALUES['key_provider']
        self.mock_encryption_data_key.encrypted_data_key = VALUES['encrypted_data_key']
        pt_stream = io.BytesIO(self.plaintext)
        test_encryptor = StreamEncryptor(
            source=pt_stream,
            key_provider=self.mock_key_provider
        )
        test_encryptor.encryption_data_key = self.mock_encryption_data_key
        test_encryptor.close()
        mock_close.assert_called_once_with()
