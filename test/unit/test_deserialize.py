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
"""Unit test suite for aws_encryption_sdk.deserialize"""
import io
import unittest

import pytest
import six
from cryptography.exceptions import InvalidTag
from mock import MagicMock, patch, sentinel

import aws_encryption_sdk.internal.formatting.deserialize
from aws_encryption_sdk.exceptions import NotSupportedError, SerializationError, UnknownIdentityError
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.internal.structures import EncryptedData

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestDeserialize(unittest.TestCase):
    def setUp(self):
        self.mock_wrapping_algorithm = MagicMock()
        self.mock_wrapping_algorithm.algorithm.iv_len = VALUES["iv_len"]

        # Set up mock header
        self.mock_header = MagicMock()
        # Set up mock key provider
        self.mock_key_provider = MagicMock()
        self.mock_key_provider.decrypt_data_key_from_list.return_value = VALUES["data_key_obj"]
        # Set up BytesIO patch
        self.mock_bytesio = MagicMock()
        # Set up crypto patch
        self.mock_decrypt_patcher = patch("aws_encryption_sdk.internal.formatting.deserialize.decrypt")
        self.mock_decrypt = self.mock_decrypt_patcher.start()
        # Set up encryption_context patch
        self.mock_deserialize_ec_patcher = patch(
            "aws_encryption_sdk.internal.formatting.deserialize.deserialize_encryption_context"
        )
        self.mock_deserialize_ec = self.mock_deserialize_ec_patcher.start()
        self.mock_deserialize_ec.return_value = VALUES["updated_encryption_context"]
        # Set up mock verifier
        self.mock_verifier = MagicMock()
        self.mock_verifier.update.return_value = None

    def tearDown(self):
        self.mock_decrypt_patcher.stop()
        self.mock_deserialize_ec_patcher.stop()

    def test_validate_header_valid(self):
        """Validate that the validate_header function behaves
            as expected for a valid header.
        """
        self.mock_bytesio.read.return_value = VALUES["header"]
        self.mock_decrypt.return_value = sentinel.decrypted
        aws_encryption_sdk.internal.formatting.deserialize.validate_header(
            header=VALUES["deserialized_header_block"],
            header_auth=VALUES["deserialized_header_auth_block"],
            raw_header=VALUES["header"],
            data_key=sentinel.encryption_key,
        )
        self.mock_decrypt.assert_called_once_with(
            algorithm=VALUES["deserialized_header_block"].algorithm,
            key=sentinel.encryption_key,
            encrypted_data=VALUES["header_auth_base"],
            associated_data=VALUES["header"],
        )

    def test_validate_header_invalid(self):
        """Validate that the validate_header function behaves
            as expected for a valid header.
        """
        self.mock_decrypt.side_effect = InvalidTag()
        with six.assertRaisesRegex(self, SerializationError, "Header authorization failed"):
            aws_encryption_sdk.internal.formatting.deserialize.validate_header(
                header=VALUES["deserialized_header_block"],
                header_auth=VALUES["deserialized_header_auth_block"],
                raw_header=VALUES["header"],
                data_key=VALUES["data_key_obj"],
            )

    def test_deserialize_header_unknown_object_type(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown object type.
        """
        with six.assertRaisesRegex(self, NotSupportedError, "Unsupported type *"):
            stream = io.BytesIO(VALUES["serialized_header_invalid_object_type"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_unknown_version(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown message version.
        """
        with six.assertRaisesRegex(self, NotSupportedError, "Unsupported version *"):
            stream = io.BytesIO(VALUES["serialized_header_invalid_version"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    @patch("aws_encryption_sdk.internal.formatting.deserialize.AlgorithmSuite.get_by_id")
    def test_deserialize_header_unsupported_data_encryption_algorithm(self, mock_algorithm_get):
        """Validate that the deserialize_header function behaves
            as expected for an unsupported/disallowed algorithm.
        """
        mock_unsupported_algorithm = MagicMock()
        mock_unsupported_algorithm.allowed = False
        mock_algorithm_get.return_value = mock_unsupported_algorithm
        with six.assertRaisesRegex(self, NotSupportedError, "Unsupported algorithm *"):
            stream = io.BytesIO(VALUES["serialized_header_disallowed_algorithm"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    @patch("aws_encryption_sdk.internal.formatting.deserialize.AlgorithmSuite.get_by_id")
    def test_deserialize_header_unknown_data_encryption_algorithm(self, mock_algorithm_get):
        """Validate that the deserialize_header function behaves
            as expected for an unknown algorithm.
        """
        mock_algorithm_get.side_effect = KeyError()
        with six.assertRaisesRegex(self, UnknownIdentityError, "Unknown algorithm *"):
            stream = io.BytesIO(VALUES["serialized_header_invalid_algorithm"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_unknown_content_type(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown content type.
        """
        with six.assertRaisesRegex(self, UnknownIdentityError, "Unknown content type *"):
            stream = io.BytesIO(VALUES["serialized_header_unknown_content_type"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_invalid_reserved_space(self):
        """Validate that the deserialize_header function behaves
            as expected for an invalid value in the reserved
            space (formerly content AAD).
        """
        with six.assertRaisesRegex(
            self, SerializationError, "Content AAD length field is currently unused, its value must be always 0"
        ):
            stream = io.BytesIO(VALUES["serialized_header_bad_reserved_space"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_bad_iv_len(self):
        """Validate that the deserialize_header function behaves
            as expected for bad IV length (incompatible with
            specified algorithm).
        """
        with six.assertRaisesRegex(self, SerializationError, "Specified IV length *"):
            stream = io.BytesIO(VALUES["serialized_header_bad_iv_len"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_framed_bad_frame_length(self):
        """Validate that the deserialize_header function behaves
            as expected for bad frame length values (greater than
            the default maximum).
        """
        with six.assertRaisesRegex(self, SerializationError, "Specified frame length larger than allowed maximum: *"):
            stream = io.BytesIO(VALUES["serialized_header_bad_frame_len"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_non_framed_bad_frame_length(self):
        """Validate that the deserialize_header function behaves
            as expected for bad frame length values for non-framed
            messages (non-zero).
        """
        with six.assertRaisesRegex(self, SerializationError, "Non-zero frame length found for non-framed message"):
            stream = io.BytesIO(VALUES["serialized_non_framed_header_bad_frame_len"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)

    def test_deserialize_header_valid(self):
        """Validate that the deserialize_header function behaves
            as expected for a valid header.
        """
        stream = io.BytesIO(VALUES["serialized_header_small_frame"])
        test_header, test_raw_header = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        assert test_header == VALUES["deserialized_header_frame"]
        assert test_raw_header == VALUES["serialized_header_small_frame"]

    def test_deserialize_header_auth(self):
        """Validate that the deserialize_header_auth function
            behaves as expected for a valid header auth.
        """
        stream = io.BytesIO(VALUES["serialized_header_auth"])
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header_auth(
            stream=stream, algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16
        )
        assert test == VALUES["deserialized_header_auth_block"]

    def test_deserialize_body_frame_standard(self):
        """Validate that the deserialize_body_frame function
            behaves as expected for a valid body frame.
        """
        stream = io.BytesIO(VALUES["serialized_frame"])
        test_body, test_final = aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
            stream=stream, header=VALUES["deserialized_header_frame"]
        )
        assert test_body == VALUES["deserialized_body_frame_1"]
        assert not test_final

    def test_deserialize_body_frame_final(self):
        """Validate that the deserialize_body_frame function
            behaves as expected for a valid final body frame.
        """
        stream = io.BytesIO(VALUES["serialized_final_frame"])
        test_body, test_final = aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
            stream=stream, header=VALUES["deserialized_header_frame_huge_frame"]
        )
        assert test_body == VALUES["deserialized_body_final_frame_single"]
        assert test_final

    def test_deserialize_body_frame_final_invalid_final_frame_length(self):
        """Validate that the deserialize_body_frame function
            behaves as expected for a valid final body frame.
        """
        stream = io.BytesIO(VALUES["serialized_final_frame_bad_length"])
        with six.assertRaisesRegex(self, SerializationError, "Invalid final frame length: *"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
                stream=stream, header=VALUES["deserialized_header_frame"]
            )

    def test_deserialize_footer_no_verifier(self):
        """Vaidate that the deserialize_footer function behaves
            as expected when called with no verifier.
        """
        stream = io.BytesIO(VALUES["serialized_footer"])
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream)
        assert test == VALUES["deserialized_empty_footer"]

    def test_deserialize_footer(self):
        """Vaidate that the deserialize_footer function behaves
            as expected when called with a verifier.
        """
        stream = io.BytesIO(VALUES["serialized_footer"])
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream, self.mock_verifier)
        self.mock_verifier.verify.assert_called_once_with(VALUES["signature"])
        assert test == VALUES["deserialized_footer"]

    def test_deserialize_footer_verifier_no_footer(self):
        """Vaidate that the deserialize_footer function behaves
            as expected when called with a verifier but a message
            with no footer.
        """
        stream = io.BytesIO(b"")
        with six.assertRaisesRegex(self, SerializationError, "No signature found in message"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream, self.mock_verifier)

    @patch("aws_encryption_sdk.internal.formatting.deserialize.struct")
    def test_unpack_values(self, mock_struct):
        """Validate that the unpack_values function behaves as expected."""
        self.mock_bytesio.read.return_value = sentinel.message_bytes
        mock_struct.calcsize.return_value = sentinel.size
        mock_struct.unpack.return_value = sentinel.unpacked
        test = aws_encryption_sdk.internal.formatting.deserialize.unpack_values(
            format_string=sentinel.format_string, stream=self.mock_bytesio, verifier=self.mock_verifier
        )
        mock_struct.calcsize.assert_called_once_with(sentinel.format_string)
        self.mock_bytesio.read.assert_called_once_with(sentinel.size)
        mock_struct.unpack.assert_called_once_with(sentinel.format_string, sentinel.message_bytes)
        self.mock_verifier.update.assert_called_once_with(sentinel.message_bytes)
        assert test == sentinel.unpacked

    @patch("aws_encryption_sdk.internal.formatting.deserialize.struct")
    def test_unpack_values_no_verifier(self, mock_struct):
        """Validate that the unpack_values function
            behaves as expected when no verifier is
            provided.
        """
        self.mock_bytesio.read.return_value = sentinel.message_bytes
        mock_struct.calcsize.return_value = sentinel.size
        mock_struct.unpack.return_value = sentinel.unpacked
        test = aws_encryption_sdk.internal.formatting.deserialize.unpack_values(
            format_string=sentinel.format_string, stream=self.mock_bytesio
        )
        assert test == sentinel.unpacked

    def test_deserialize_wrapped_key_asymmetric(self):
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"]["wrapped_encrypted_data_key_asymmetric"],
        )
        assert test == EncryptedData(iv=None, ciphertext=VALUES["wrapped_keys"]["raw"]["ciphertext"], tag=None)

    def test_deserialize_wrapped_key_symmetric(self):
        test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"]["wrapped_encrypted_data_key_symmetric"],
        )
        assert test == EncryptedData(
            iv=VALUES["wrapped_keys"]["raw"]["iv"],
            ciphertext=VALUES["wrapped_keys"]["raw"]["ciphertext"],
            tag=VALUES["wrapped_keys"]["raw"]["tag"],
        )

    def test_deserialize_wrapped_key_symmetric_wrapping_key_mismatch(self):
        with six.assertRaisesRegex(self, SerializationError, "Master Key mismatch for wrapped data key"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=b"asifuhasjaskldjfhlsakdfj",
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"]["wrapped_encrypted_data_key_asymmetric"],
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_info(self):
        with six.assertRaisesRegex(self, SerializationError, "Malformed key info: key info missing data"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_info"
                ],
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_iv_len_mismatch(self):
        with six.assertRaisesRegex(self, SerializationError, "Wrapping AlgorithmSuite mismatch for wrapped data key"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_bad_iv_len"
                ],
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_iv(self):
        with six.assertRaisesRegex(self, SerializationError, "Malformed key info: incomplete iv"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_iv"
                ],
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_tag(self):
        with six.assertRaisesRegex(self, SerializationError, "Malformed key info: incomplete ciphertext or tag"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_tag"
                ],
            )

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_tag2(self):
        with six.assertRaisesRegex(self, SerializationError, "Malformed key info: incomplete ciphertext or tag"):
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_tag2"
                ],
            )
