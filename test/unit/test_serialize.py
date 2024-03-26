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
"""Unit test suite for aws_encryption_sdk.internal.formatting.serialize"""
import pytest
from mock import MagicMock, patch, sentinel

import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.identifiers import ContentAADString, SerializationVersion
from aws_encryption_sdk.internal.defaults import MAX_FRAME_COUNT
from aws_encryption_sdk.internal.structures import EncryptedData
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize(
    "sequence_number, error_message",
    (
        (-1, r"Frame sequence number must be greater than 0"),
        (0, r"Frame sequence number must be greater than 0"),
        (MAX_FRAME_COUNT + 1, r"Max frame count exceeded"),
    ),
)
def test_serialize_frame_invalid_sequence_number(sequence_number, error_message):
    with pytest.raises(SerializationError) as excinfo:
        aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=None,
            plaintext=None,
            message_id=None,
            data_encryption_key=None,
            frame_length=None,
            sequence_number=sequence_number,
            is_final_frame=None,
        )

    excinfo.match(error_message)


class TestSerialize(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.encryption_algorithm.block_size = VALUES["block_size"]
        self.mock_algorithm.algorithm_id = VALUES["algorithm_id"]
        self.mock_algorithm.iv_len = VALUES["iv_len"]
        self.mock_algorithm.tag_len = self.mock_algorithm.auth_len = VALUES["tag_len"]

        self.mock_valid_sequence_number = MagicMock(
            __lt__=MagicMock(return_value=False), __gt__=MagicMock(return_value=False)
        )

        self.mock_key_provider = MasterKeyInfo(provider_id=VALUES["provider_id"], key_info=VALUES["key_info"])
        self.mock_wrapping_algorithm = MagicMock()
        self.mock_wrapping_algorithm.algorithm = self.mock_algorithm
        # Set up encryption_context patch
        self.mock_serialize_acc_patcher = patch(
            "aws_encryption_sdk.internal.formatting.serialize.aws_encryption_sdk.internal.formatting.encryption_context"
        )
        self.mock_serialize_acc = self.mock_serialize_acc_patcher.start()
        self.mock_serialize_acc.serialize_encryption_context.return_value = VALUES["serialized_encryption_context"]
        # Set up crypto patch
        self.mock_encrypt_patcher = patch("aws_encryption_sdk.internal.formatting.serialize.encrypt")
        self.mock_encrypt = self.mock_encrypt_patcher.start()
        # Set up validate_frame_length patch
        self.mock_valid_frame_length_patcher = patch(
            "aws_encryption_sdk.internal.formatting.serialize.aws_encryption_sdk.internal.utils.validate_frame_length"
        )
        self.mock_valid_frame_length = self.mock_valid_frame_length_patcher.start()
        self.mock_required_ec_bytes = MagicMock()
        # Set up mock signer
        self.mock_signer = MagicMock()
        self.mock_signer.update.return_value = None
        self.mock_signer.finalize.return_value = VALUES["signature"]
        yield
        # Run tearDown
        self.mock_serialize_acc_patcher.stop()
        self.mock_encrypt_patcher.stop()
        self.mock_valid_frame_length_patcher.stop()

    def test_serialize_header_v1(self):
        """Validate that the _serialize_header function
        behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=VALUES["deserialized_header_small_frame"], signer=self.mock_signer
        )
        self.mock_serialize_acc.serialize_encryption_context.assert_called_once_with(
            VALUES["updated_encryption_context"]
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_header_small_frame"])
        assert test == VALUES["serialized_header_small_frame"]

    def test_serialize_header_v1_no_signer(self):
        """Validate that the _serialize_header function
        behaves as expected when called with no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=VALUES["deserialized_header_small_frame"]
        )

    def test_serialize_header_v2(self):
        """Validate that the _serialize_header_v2 function
        behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=VALUES["deserialized_header_v2_committing"], signer=self.mock_signer
        )
        self.mock_serialize_acc.serialize_encryption_context.assert_called_once_with(
            VALUES["updated_encryption_context"]
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_header_v2_committing"])
        assert test == VALUES["serialized_header_v2_committing"]

    def test_serialize_header_v2_no_signer(self):
        """Validate that the _serialize_header function
        behaves as expected when called with no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=VALUES["deserialized_header_v2_committing"]
        )

    @patch("aws_encryption_sdk.internal.formatting.serialize.header_auth_iv")
    def test_serialize_header_auth_v1(self, mock_header_auth_iv):
        """Validate that the _create_header_auth function
        behaves as expected for SerializationVersion.V1.
        """
        self.mock_encrypt.return_value = VALUES["header_auth_base"]
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            version=SerializationVersion.V1,
            algorithm=self.mock_algorithm,
            header=VALUES["serialized_header"],
            data_encryption_key=sentinel.encryption_key,
            signer=self.mock_signer,
        )
        self.mock_encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=sentinel.encryption_key,
            plaintext=b"",
            associated_data=VALUES["serialized_header"],
            iv=mock_header_auth_iv.return_value,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_header_auth"])
        assert test == VALUES["serialized_header_auth"]

    def test_serialize_header_auth_v1_no_signer(self):
        """Validate that the _create_header_auth function
        behaves as expected when called with no signer
        for SerializationVersion.V1.
        """
        self.mock_encrypt.return_value = VALUES["header_auth_base"]
        aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            version=SerializationVersion.V1,
            algorithm=self.mock_algorithm,
            header=VALUES["serialized_header"],
            data_encryption_key=VALUES["data_key_obj"],
        )

    @patch("aws_encryption_sdk.internal.formatting.serialize.header_auth_iv")
    def test_GIVEN_required_ec_bytes_WHEN_serialize_header_auth_v1_THEN_aad_has_required_ec_bytes(self, mock_header_auth_iv):
        """Validate that the _create_header_auth function
        behaves as expected for SerializationVersion.V1
        when required_ec_bytes are provided.
        """
        self.mock_encrypt.return_value = VALUES["header_auth_base"]
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            version=SerializationVersion.V1,
            algorithm=self.mock_algorithm,
            header=VALUES["serialized_header"],
            data_encryption_key=sentinel.encryption_key,
            signer=self.mock_signer,
            required_ec_bytes=self.mock_required_ec_bytes,
        )
        self.mock_encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=sentinel.encryption_key,
            plaintext=b"",
            associated_data=VALUES["serialized_header"] + self.mock_required_ec_bytes,
            iv=mock_header_auth_iv.return_value,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_header_auth"])
        assert test == VALUES["serialized_header_auth"]

    @patch("aws_encryption_sdk.internal.formatting.serialize.header_auth_iv")
    def test_serialize_header_auth_v2(self, mock_header_auth_iv):
        """Validate that the _create_header_auth function
        behaves as expected for SerializationVersion.V2.
        """
        self.mock_encrypt.return_value = VALUES["header_auth_base"]
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            version=SerializationVersion.V2,
            algorithm=self.mock_algorithm,
            header=VALUES["serialized_header_v2_committing"],
            data_encryption_key=sentinel.encryption_key,
            signer=self.mock_signer,
        )
        self.mock_encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=sentinel.encryption_key,
            plaintext=b"",
            associated_data=VALUES["serialized_header_v2_committing"],
            iv=mock_header_auth_iv.return_value,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_header_auth_v2"])
        assert test == VALUES["serialized_header_auth_v2"]

    def test_serialize_header_auth_v2_no_signer(self):
        """Validate that the _create_header_auth function
        behaves as expected when called with no signer
        for SerializationVersion.V1.
        """
        self.mock_encrypt.return_value = VALUES["header_auth_base"]
        aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            version=SerializationVersion.V2,
            algorithm=self.mock_algorithm,
            header=VALUES["serialized_header_v2_committing"],
            data_encryption_key=VALUES["data_key_obj"],
        )

    @patch("aws_encryption_sdk.internal.formatting.serialize.header_auth_iv")
    def test_GIVEN_required_ec_bytes_WHEN_serialize_header_auth_v2_THEN_aad_has_required_ec_bytes(self, mock_header_auth_iv):
        """Validate that the _create_header_auth function
        behaves as expected for SerializationVersion.V2.
        """
        self.mock_encrypt.return_value = VALUES["header_auth_base"]
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            version=SerializationVersion.V2,
            algorithm=self.mock_algorithm,
            header=VALUES["serialized_header_v2_committing"],
            data_encryption_key=sentinel.encryption_key,
            signer=self.mock_signer,
            required_ec_bytes=self.mock_required_ec_bytes,
        )
        self.mock_encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=sentinel.encryption_key,
            plaintext=b"",
            associated_data=VALUES["serialized_header_v2_committing"] + self.mock_required_ec_bytes,
            iv=mock_header_auth_iv.return_value,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_header_auth_v2"])
        assert test == VALUES["serialized_header_auth_v2"]

    def test_serialize_non_framed_open(self):
        """Validate that the serialize_non_framed_open
        function behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_non_framed_open(
            algorithm=self.mock_algorithm,
            iv=VALUES["final_frame_base"].iv,
            plaintext_length=len(VALUES["data_128"]),
            signer=self.mock_signer,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_non_framed_start"])
        assert test == VALUES["serialized_non_framed_start"]

    def test_serialize_non_framed_open_no_signer(self):
        """Validate that the serialize_non_framed_open
        function behaves as expected when called with
        no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_non_framed_open(
            algorithm=self.mock_algorithm, iv=VALUES["final_frame_base"].iv, plaintext_length=len(VALUES["data_128"])
        )

    def test_serialize_non_framed_close(self):
        """Validate that the serialize_non_framed_close
        function behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_non_framed_close(
            tag=VALUES["final_frame_base"].tag, signer=self.mock_signer
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_non_framed_close"])
        assert test == VALUES["serialized_non_framed_close"]

    def test_serialize_non_framed_close_no_signer(self):
        """Validate that the serialize_non_framed_close
        function behaves as expected when called with
        no signer.
        """
        aws_encryption_sdk.internal.formatting.serialize.serialize_non_framed_close(tag=VALUES["final_frame_base"].tag)

    @patch("aws_encryption_sdk.internal.formatting.serialize.frame_iv")
    def test_encrypt_and_serialize_frame(self, mock_frame_iv):
        """Validate that the _encrypt_and_serialize_frame
        function behaves as expected for a normal frame.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES["frame_aac"]
        self.mock_encrypt.return_value = VALUES["frame_base"]
        source_plaintext = VALUES["data_128"] * 2
        test_serialized, test_remainder = aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=source_plaintext,
            message_id=VALUES["message_id"],
            data_encryption_key=sentinel.encryption_key,
            frame_length=VALUES["small_frame_length"],
            sequence_number=self.mock_valid_sequence_number,
            is_final_frame=False,
            signer=self.mock_signer,
        )
        self.mock_serialize_acc.assemble_content_aad.assert_called_once_with(
            message_id=VALUES["message_id"],
            aad_content_string=ContentAADString.FRAME_STRING_ID,
            seq_num=self.mock_valid_sequence_number,
            length=VALUES["small_frame_length"],
        )
        mock_frame_iv.assert_called_once_with(self.mock_algorithm, self.mock_valid_sequence_number)
        self.mock_encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=sentinel.encryption_key,
            plaintext=source_plaintext[: VALUES["small_frame_length"]],
            associated_data=VALUES["frame_aac"],
            iv=mock_frame_iv.return_value,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_frame"])
        assert test_serialized == VALUES["serialized_frame"]
        assert test_remainder == source_plaintext[VALUES["small_frame_length"] :]

    def test_encrypt_and_serialize_frame_no_signer(self):
        """Validate that the _encrypt_and_serialize_frame
        function behaves as expected for a normal frame
        when called with no signer.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES["frame_aac"]
        self.mock_encrypt.return_value = VALUES["frame_base"]
        aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=VALUES["data_128"] * 2,
            message_id=VALUES["message_id"],
            data_encryption_key=VALUES["data_key_obj"],
            frame_length=len(VALUES["data_128"]),
            is_final_frame=False,
            sequence_number=self.mock_valid_sequence_number,
        )

    @patch("aws_encryption_sdk.internal.formatting.serialize.frame_iv")
    def test_encrypt_and_serialize_frame_final(self, mock_frame_iv):
        """Validate that the _encrypt_and_serialize_frame
        function behaves as expected for a final frame.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES["final_frame_aac"]
        self.mock_encrypt.return_value = VALUES["final_frame_base"]
        test_serialized, test_remainder = aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=VALUES["data_128"],
            message_id=VALUES["message_id"],
            data_encryption_key=sentinel.encryption_key,
            frame_length=len(VALUES["data_128"]),
            sequence_number=self.mock_valid_sequence_number,
            is_final_frame=True,
            signer=self.mock_signer,
        )
        self.mock_serialize_acc.assemble_content_aad.assert_called_once_with(
            message_id=VALUES["message_id"],
            aad_content_string=ContentAADString.FINAL_FRAME_STRING_ID,
            seq_num=self.mock_valid_sequence_number,
            length=len(VALUES["data_128"]),
        )
        mock_frame_iv.assert_called_once_with(self.mock_algorithm, self.mock_valid_sequence_number)
        self.mock_encrypt.assert_called_once_with(
            algorithm=self.mock_algorithm,
            key=sentinel.encryption_key,
            plaintext=VALUES["data_128"],
            associated_data=VALUES["final_frame_aac"],
            iv=mock_frame_iv.return_value,
        )
        self.mock_signer.update.assert_called_once_with(VALUES["serialized_final_frame"])
        assert test_serialized == VALUES["serialized_final_frame"]
        assert test_remainder == b""

    def test_encrypt_and_serialize_frame_final_no_signer(self):
        """Validate that the _encrypt_and_serialize_frame
        function behaves as expected for a final frame
        when called with no signer.
        """
        self.mock_serialize_acc.assemble_content_aad.return_value = VALUES["final_frame_aac"]
        self.mock_encrypt.return_value = VALUES["final_frame_base"]
        aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
            algorithm=self.mock_algorithm,
            plaintext=VALUES["data_128"],
            message_id=VALUES["message_id"],
            data_encryption_key=VALUES["data_key_obj"],
            frame_length=len(VALUES["data_128"]),
            is_final_frame=True,
            sequence_number=self.mock_valid_sequence_number,
        )

    def test_serialize_footer_with_signer(self):
        """Validate that the serialize_footer function behaves as expected
        when called with a signer.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_footer(self.mock_signer)
        self.mock_signer.finalize.assert_called_with()
        assert test == VALUES["serialized_footer"]

    def test_serialize_footer_no_signer(self):
        """Validate that the serialize_footer function behaves as expected
        when called without a signer.
        """
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_footer(None)
        assert test == b""

    def test_serialize_wrapped_key_asymmetric(self):
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.mock_key_provider,
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            encrypted_wrapped_key=EncryptedData(iv=None, ciphertext=VALUES["data_128"], tag=None),
        )
        assert test == EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id=VALUES["provider_id"], key_info=VALUES["wrapped_keys"]["raw"]["key_info"]
            ),
            encrypted_data_key=VALUES["data_128"],
        )

    def test_serialize_wrapped_key_symmetric(self):
        test = aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.mock_key_provider,
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
            encrypted_wrapped_key=VALUES["wrapped_keys"]["structures"]["wrapped_encrypted_data"],
        )
        assert test == EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id=VALUES["provider_id"], key_info=VALUES["wrapped_keys"]["serialized"]["key_info"]
            ),
            encrypted_data_key=VALUES["wrapped_keys"]["serialized"]["key_ciphertext"],
        )
