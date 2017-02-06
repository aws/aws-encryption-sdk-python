"""
    Unit test suite for aws_encryption_sdk.deserialize
"""
import io
import unittest
from cryptography.exceptions import InvalidTag
from mock import MagicMock, patch, sentinel
import six
from aws_encryption_sdk.exceptions import SerializationError, UnknownIdentityError, NotSupportedError
from aws_encryption_sdk.internal.identifiers import Algorithm
from aws_encryption_sdk.internal.structures import EncryptedData
import aws_encryption_sdk.internal.formatting.deserialize
from .test_values import VALUES


class TestDeserialize(unittest.TestCase):

    def setUp(self):
        self.mock_wrapping_algorithm = MagicMock()
        self.mock_wrapping_algorithm.algorithm.iv_len = VALUES['iv_len']

        # Set up mock header
        self.mock_header = MagicMock()
        # Set up mock key provider
        self.mock_key_provider = MagicMock()
        self.mock_key_provider.decrypt_data_key_from_list.return_value = VALUES['data_key_obj']
        # Set up BytesIO patch
        self.mock_bytesio = MagicMock()
        # Set up crypto patch
        self.mock_crypto_patcher = patch(
            'aws_encryption_sdk.internal.formatting.deserialize.aws_encryption_sdk.internal.crypto'
        )
        self.mock_crypto = self.mock_crypto_patcher.start()
        # Set up encryption_context patch
        self.mock_deserialize_ec_patcher = patch(
            'aws_encryption_sdk.internal.formatting.deserialize.deserialize_encryption_context'
        )
        self.mock_deserialize_ec = self.mock_deserialize_ec_patcher.start()
        self.mock_deserialize_ec.return_value = VALUES['updated_encryption_context']
        # Set up verifier patch
        self.mock_verifier_patcher = patch(
            'aws_encryption_sdk.internal.formatting.deserialize.aws_encryption_sdk.internal.crypto.Verifier'
        )
        self.mock_verifier_class = self.mock_verifier_patcher.start()
        self.mock_verifier = MagicMock()
        self.mock_verifier.update.return_value = None
        self.mock_verifier_class.from_encoded_point.return_value = self.mock_verifier

    def tearDown(self):
        self.mock_crypto_patcher.stop()
        self.mock_deserialize_ec_patcher.stop()
        self.mock_verifier_patcher.stop()

    def test_verifier_from_header(self):
        """Validate that the verifier_from_header function behaves
            as expected.
        """
        self.mock_header.encryption_context.get.return_value = sentinel.encoded_point
        self.mock_header.algorithm = sentinel.algorithm
        test = aws_encryption_sdk.internal.formatting.deserialize.verifier_from_header(self.mock_header)
        self.mock_verifier_class.from_encoded_point.assert_called_once_with(
            algorithm=sentinel.algorithm,
            encoded_point=sentinel.encoded_point
        )
        assert test is self.mock_verifier

    def test_verifier_from_header_no_verifier(self):
        """Validate that the verifier_from_header function behaves
            as expected when called with a header with no encoded
            point and an algorithm with no curve type.
        """
        self.mock_header.encryption_context.get.return_value = None
        self.mock_header.algorithm.signing_algorithm_info = None
        test = aws_encryption_sdk.internal.formatting.deserialize.verifier_from_header(self.mock_header)
        assert test is None

    def test_verifier_from_header_verifier_required_but_no_point(self):
        """Validate that the verifier_from_header function behaves
            as expected when called with a header with no encoded
            point and an algorithm with a curve type.
        """
        self.mock_header.encryption_context.get.return_value = None
        self.mock_header.algorithm.signing_algorithm_info = sentinel.signing_algorithm_info
        with six.assertRaisesRegex(
            self,
            SerializationError,
            'No public key found in header for message encrypted with ECDSA algorithm: *'
        ):
            aws_encryption_sdk.internal.formatting.deserialize.verifier_from_header(self.mock_header)

    def test_validate_header_valid(self):
        """Validate that the validate_header function behaves
            as expected for a valid header.
        """
        self.mock_bytesio.read.return_value = VALUES['header']
        self.mock_crypto.decrypt.return_value = sentinel.decrypted
        aws_encryption_sdk.internal.formatting.deserialize.validate_header(
            header=VALUES['deserialized_header_block'],
            header_auth=VALUES['deserialized_header_auth_block'],
            stream=self.mock_bytesio,
            header_start=0,
            header_end=len(VALUES['header']),
            data_key=VALUES['data_key_obj']
        )
        self.mock_crypto.decrypt.assert_called_once_with(
            algorithm=VALUES['deserialized_header_block'].algorithm,
            key=VALUES['data_key'],
            encrypted_data=VALUES['header_auth_base'],
            associated_data=VALUES['header'],
            message_id=VALUES['message_id']
        )

    def test_validate_header_invalid(self):
        """Validate that the validate_header function behaves
            as expected for a valid header.
        """
        self.mock_crypto.decrypt.side_effect = InvalidTag()
        with six.assertRaisesRegex(self, SerializationError, 'Header authorization failed'):
            aws_encryption_sdk.internal.formatting.deserialize.validate_header(
                header=VALUES['deserialized_header_block'],
                header_auth=VALUES['deserialized_header_auth_block'],
                stream=self.mock_bytesio,
                header_start=0,
                header_end=len(VALUES['header']),
                data_key=VALUES['data_key_obj']
            )

    def test_deserialize_header_unknown_object_type(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown object type.
        """
        with six.assertRaisesRegex(self, NotSupportedError, 'Unsupported type *'):
            stream = io.BytesIO(VALUES['serialized_header_invalid_object_type'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_unknown_version(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown message version.
        """
        with six.assertRaisesRegex(self, NotSupportedError, 'Unsupported version *'):
            stream = io.BytesIO(VALUES['serialized_header_invalid_version'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    @patch('aws_encryption_sdk.internal.formatting.deserialize.Algorithm.get_by_id')
    def test_deserialize_header_unsupported_data_encryption_algorithm(self, mock_algorithm_get):
        """Validate that the deserialize_header function behaves
            as expected for an unsupported/disallowed algorithm.
        """
        mock_unsupported_algorithm = MagicMock()
        mock_unsupported_algorithm.allowed = False
        mock_algorithm_get.return_value = mock_unsupported_algorithm
        with six.assertRaisesRegex(self, NotSupportedError, 'Unsupported algorithm *'):
            stream = io.BytesIO(VALUES['serialized_header_disallowed_algorithm'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    @patch('aws_encryption_sdk.internal.formatting.deserialize.Algorithm.get_by_id')
    def test_deserialize_header_unknown_data_encryption_algorithm(self, mock_algorithm_get):
        """Validate that the deserialize_header function behaves
            as expected for an unknown algorithm.
        """
        mock_algorithm_get.side_effect = KeyError()
        with six.assertRaisesRegex(self, UnknownIdentityError, 'Unknown algorithm *'):
            stream = io.BytesIO(VALUES['serialized_header_invalid_algorithm'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_unknown_content_type(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown content type.
        """
        with six.assertRaisesRegex(self, UnknownIdentityError, 'Unknown content type *'):
            stream = io.BytesIO(VALUES['serialized_header_unknown_content_type'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_invalid_reserved_space(self):
        """Validate that the deserialize_header function behaves
            as expected for an invalid value in the reserved
            space (formerly content AAD).
        """
        with six.assertRaisesRegex(
            self,
            SerializationError,
            'Content AAD length field is currently unused, its value must be always 0'
        ):
            stream = io.BytesIO(VALUES['serialized_header_bad_reserved_space'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_bad_iv_len(self):
        """Validate that the deserialize_header function behaves
            as expected for bad IV length (incompatible with
            specified algorithm).
        """
        with six.assertRaisesRegex(self, SerializationError, 'Specified IV length *'):
            stream = io.BytesIO(VALUES['serialized_header_bad_iv_len'])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_valid(self):
        """Validate that the deserialize_header function behaves
            as expected for a valid header.
        """
        stream = io.BytesIO(VALUES['serialized_header_small_frame'])
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        assert test == VALUES['deserialized_header_frame']

    def test_deserialize_header_auth(self):
        """Validate that the deserialize_header_auth function
            behaves as expected for a valid header auth.
        """
        stream = io.BytesIO(VALUES['serialized_header_auth'])
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header_auth(
            stream=stream,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16
        )
        assert test == VALUES['deserialized_header_auth_block']

    def test_deserialize_body_frame_standard(self):
        """Validate that the deserialize_body_frame function
            behaves as expected for a valid body frame.
        """
        stream = io.BytesIO(VALUES['serialized_frame'])
        test_body, test_final = aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
            stream=stream,
            header=VALUES['deserialized_header_frame']
        )
        assert test_body == VALUES['deserialized_body_frame_1']
        assert not test_final

    def test_deserialize_body_frame_final(self):
        """Validate that the deserialize_body_frame function
            behaves as expected for a valid final body frame.
        """
        stream = io.BytesIO(VALUES['serialized_final_frame'])
        test_body, test_final = aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
            stream=stream,
            header=VALUES['deserialized_header_frame']
        )
        assert test_body == VALUES['deserialized_body_final_frame_single']
        assert test_final

    def test_deserialize_footer_no_verifier(self):
        """Vaidate that the deserialize_footer function behaves
            as expected when called with no verifier.
        """
        stream = io.BytesIO(VALUES['serialized_footer'])
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream)
        assert test == VALUES['deserialized_footer']

    def test_deserialize_footer(self):
        """Vaidate that the deserialize_footer function behaves
            as expected when called with a verifier.
        """
        stream = io.BytesIO(VALUES['serialized_footer'])
        aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream, self.mock_verifier)
        self.mock_verifier.set_signature.assert_called_once_with(VALUES['signature'])
        self.mock_verifier.verify.assert_called_once_with()

    def test_deserialize_footer_verifier_no_footer(self):
        """Vaidate that the deserialize_footer function behaves
            as expected when called with a verifier but a message
            with no footer.
        """
        stream = io.BytesIO(b'')
        with six.assertRaisesRegex(self, SerializationError, 'No signature found in message'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream, self.mock_verifier)

    @patch('aws_encryption_sdk.internal.formatting.deserialize.struct')
    def test_unpack_values(self, mock_struct):
        """Validate that the unpack_values function behaves as expected."""
        self.mock_bytesio.read.return_value = sentinel.message_bytes
        mock_struct.calcsize.return_value = sentinel.size
        mock_struct.unpack.return_value = sentinel.unpacked
        test = aws_encryption_sdk.internal.formatting.deserialize.unpack_values(
            format_string=sentinel.format_string,
            stream=self.mock_bytesio,
            verifier=self.mock_verifier
        )
        mock_struct.calcsize.assert_called_once_with(sentinel.format_string)
        self.mock_bytesio.read.assert_called_once_with(sentinel.size)
        mock_struct.unpack.assert_called_once_with(
            sentinel.format_string,
            sentinel.message_bytes
        )
        self.mock_verifier.update.assert_called_once_with(sentinel.message_bytes)
        assert test == sentinel.unpacked

    @patch('aws_encryption_sdk.internal.formatting.deserialize.struct')
    def test_unpack_values_no_verifier(self, mock_struct):
        """Validate that the unpack_values function
            behaves as expected when no verifier is
            provided.
        """
        self.mock_bytesio.read.return_value = sentinel.message_bytes
        mock_struct.calcsize.return_value = sentinel.size
        mock_struct.unpack.return_value = sentinel.unpacked
        test = aws_encryption_sdk.internal.formatting.deserialize.unpack_values(
            format_string=sentinel.format_string,
            stream=self.mock_bytesio
        )
        assert test == sentinel.unpacked

    def test_deserialize_wrapped_key_asymmetric(self):
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
            wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_asymmetric']
        )
        assert test == EncryptedData(
            iv=None,
            ciphertext=VALUES['wrapped_keys']['raw']['ciphertext'],
            tag=None
        )

    def test_deserialize_wrapped_key_symmetric(self):
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
            wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_symmetric']
        )
        assert test == EncryptedData(
            iv=VALUES['wrapped_keys']['raw']['iv'],
            ciphertext=VALUES['wrapped_keys']['raw']['ciphertext'],
            tag=VALUES['wrapped_keys']['raw']['tag']
        )

    def test_deserialize_wrapped_key_symmetric_wrapping_key_mismatch(self):
        with six.assertRaisesRegex(self, SerializationError, 'Master Key mismatch for wrapped data key'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=b'asifuhasjaskldjfhlsakdfj',
                wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_asymmetric']
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_info(self):
        with six.assertRaisesRegex(self, SerializationError, 'Malformed key info: key info missing data'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
                wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_symmetric_incomplete_info']
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_iv_len_mismatch(self):
        with six.assertRaisesRegex(self, SerializationError, 'Wrapping Algorithm mismatch for wrapped data key'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
                wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_symmetric_bad_iv_len']
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_iv(self):
        with six.assertRaisesRegex(self, SerializationError, 'Malformed key info: incomplete iv'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
                wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_symmetric_incomplete_iv']
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_tag(self):
        with six.assertRaisesRegex(self, SerializationError, 'Malformed key info: incomplete ciphertext or tag'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
                wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_symmetric_incomplete_tag']
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_tag2(self):
        with six.assertRaisesRegex(self, SerializationError, 'Malformed key info: incomplete ciphertext or tag'):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES['wrapped_keys']['raw']['key_info'],
                wrapped_encrypted_key=VALUES['wrapped_keys']['structures']['wrapped_encrypted_data_key_symmetric_incomplete_tag2']
            )
