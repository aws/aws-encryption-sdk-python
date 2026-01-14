# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.internal.formatting.serialize"""
import io
import struct

import pytest
from mock import MagicMock, patch, sentinel

import aws_encryption_sdk.internal.formatting.deserialize
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.identifiers import ContentAADString, SerializationVersion
from aws_encryption_sdk.internal.defaults import MAX_FRAME_COUNT
from aws_encryption_sdk.internal.structures import EncryptedData
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]

provider_input_strings = ["", "abc", "𐀂", "abc𐀂", "𐀂abc", "秘密代码", "abc秘密代码", "秘密代码abc", "秘密代码abc𐀂", "𐀂abc秘密代码123𐀂"]

provider_input_strings_batch1 = ["", "abc", "𐀂", "abc𐀂", "𐀂abc"]
provider_input_strings_batch2 = ["秘密代码", "abc秘密代码", "秘密代码abc", "秘密代码abc𐀂", "𐀂abc秘密代码123𐀂"]


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

    @pytest.mark.parametrize("provider_id", provider_input_strings)
    @pytest.mark.parametrize("provider_info", provider_input_strings)
    def test_GIVEN_valid_encrypted_data_key_WHEN_serialize_encrypted_data_key_THEN_deserialize_equals_input(
        self,
        provider_id,
        provider_info,
    ):
        # Given: Some valid encrypted data key
        key_provider = MasterKeyInfo(provider_id=provider_id, key_info=provider_info)
        encrypted_data_key = EncryptedDataKey(
            key_provider=key_provider, encrypted_data_key=VALUES["encrypted_data_key"]
        )

        # When: serialize_encrypted_data_key
        serialized_edk = aws_encryption_sdk.internal.formatting.serialize.serialize_encrypted_data_key(
            encrypted_data_key=encrypted_data_key
        )

        # Then: Can deserialize the value
        serialized_edks = bytes()
        # Hardcode to have only 1 EDK
        serialized_edks += struct.pack(">H", 1)
        serialized_edks += serialized_edk
        # Deserialization must not raise exception
        deserialized = aws_encryption_sdk.internal.formatting.deserialize.deserialize_encrypted_data_keys(
            stream=io.BytesIO(serialized_edks)
        )
        assert deserialized == {encrypted_data_key}
        assert len(deserialized) == 1
        deserialized_edk = list(deserialized)[0]
        assert deserialized_edk.key_provider == encrypted_data_key.key_provider
        assert deserialized_edk.key_provider.provider_id == encrypted_data_key.key_provider.provider_id
        assert deserialized_edk.key_provider.key_info == encrypted_data_key.key_provider.key_info
        assert deserialized_edk.encrypted_data_key == encrypted_data_key.encrypted_data_key

    @pytest.mark.parametrize("edk_1_provider_id", provider_input_strings_batch1)
    @pytest.mark.parametrize("edk_1_provider_info", provider_input_strings_batch1)
    @pytest.mark.parametrize("edk_2_provider_id", provider_input_strings_batch1)
    @pytest.mark.parametrize("edk_2_provider_info", provider_input_strings_batch1)
    def test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs_batch1(
        self,
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info,
    ):
        self.test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs(
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info)
        
    @pytest.mark.parametrize("edk_1_provider_id", provider_input_strings_batch2)
    @pytest.mark.parametrize("edk_1_provider_info", provider_input_strings_batch2)
    @pytest.mark.parametrize("edk_2_provider_id", provider_input_strings_batch2)
    @pytest.mark.parametrize("edk_2_provider_info", provider_input_strings_batch2)        
    def test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs_batch2(
        self,
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info,
    ):
        self.test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs(
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info)

    @pytest.mark.parametrize("edk_1_provider_id", provider_input_strings_batch1)
    @pytest.mark.parametrize("edk_1_provider_info", provider_input_strings_batch1)
    @pytest.mark.parametrize("edk_2_provider_id", provider_input_strings_batch2)
    @pytest.mark.parametrize("edk_2_provider_info", provider_input_strings_batch2)
    def test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs_batch3(
        self,
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info,
    ):
        self.test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs(
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info)

    def test_GIVEN_two_distinct_valid_encrypted_data_keys_WHEN_serialize_encrypted_data_keys_THEN_deserialize_equals_inputs(  # noqa pylint: disable=line-too-long
        edk_1_provider_id,
        edk_1_provider_info,
        edk_2_provider_id,
        edk_2_provider_info,
    ):
        # pylint: disable=too-many-locals
        # Given: Two distinct valid encrypted data keys
        edk_1_key_provider = MasterKeyInfo(provider_id=edk_1_provider_id, key_info=edk_1_provider_info)
        encrypted_data_key_1 = EncryptedDataKey(
            key_provider=edk_1_key_provider, encrypted_data_key=VALUES["encrypted_data_key"]
        )

        edk_2_key_provider = MasterKeyInfo(provider_id=edk_2_provider_id, key_info=edk_2_provider_info)
        encrypted_data_key_2 = EncryptedDataKey(
            key_provider=edk_2_key_provider, encrypted_data_key=VALUES["encrypted_data_key"]
        )

        # Must be distinct
        if encrypted_data_key_1 == encrypted_data_key_2:
            return

        # When: serialize_encrypted_data_key
        serialized_edk_1 = aws_encryption_sdk.internal.formatting.serialize.serialize_encrypted_data_key(
            encrypted_data_key=encrypted_data_key_1
        )
        serialized_edk_2 = aws_encryption_sdk.internal.formatting.serialize.serialize_encrypted_data_key(
            encrypted_data_key=encrypted_data_key_2
        )

        # Then: Can deserialize the value
        serialized_edks = bytes()
        # Hardcode to have only 2 EDKs
        serialized_edks += struct.pack(">H", 2)
        serialized_edks += serialized_edk_1
        serialized_edks += serialized_edk_2
        # Deserialization must not raise exception
        deserialized = aws_encryption_sdk.internal.formatting.deserialize.deserialize_encrypted_data_keys(
            stream=io.BytesIO(serialized_edks)
        )
        assert deserialized == {encrypted_data_key_1, encrypted_data_key_2}
        assert len(deserialized) == 2
        deserialized_edk_list = list(deserialized)

        deserialized_edk_some = deserialized_edk_list[0]
        deserialized_edk_other = deserialized_edk_list[1]

        assert (
            (deserialized_edk_some == encrypted_data_key_1 and deserialized_edk_other == encrypted_data_key_2)
            or (deserialized_edk_some == encrypted_data_key_2 and deserialized_edk_other == encrypted_data_key_1)
        )

    def test_GIVEN_invalid_encrypted_data_key_WHEN_serialize_THEN_raises_UnicodeEncodeError(
        self,
    ):
        # Given: Some invalid encrypted data key

        # This is invalid because "\ud800\udc02" cannot be encoded to UTF-8.
        # This value MUST be able to be encoded to UTF-8, or serialization will fail.
        invalid_provider_string = "\ud800\udc02"

        # Then: raises UnicodeEncodeError
        with pytest.raises(UnicodeEncodeError):
            key_provider = MasterKeyInfo(provider_id=invalid_provider_string, key_info=invalid_provider_string)

            encrypted_data_key = EncryptedDataKey(
                key_provider=key_provider, encrypted_data_key=VALUES["encrypted_data_key"]
            )

            # When: serialize_encrypted_data_key
            aws_encryption_sdk.internal.formatting.serialize.serialize_encrypted_data_key(
                encrypted_data_key=encrypted_data_key
            )

        # Then: raises UnicodeEncodeError
        with pytest.raises(UnicodeEncodeError):
            key_provider = MasterKeyInfo(provider_id=invalid_provider_string, key_info="abc")

            encrypted_data_key = EncryptedDataKey(
                key_provider=key_provider, encrypted_data_key=VALUES["encrypted_data_key"]
            )

            # When: serialize_encrypted_data_key
            aws_encryption_sdk.internal.formatting.serialize.serialize_encrypted_data_key(
                encrypted_data_key=encrypted_data_key
            )

        # Then: raises UnicodeEncodeError
        with pytest.raises(UnicodeEncodeError):
            key_provider = MasterKeyInfo(provider_id="abc", key_info=invalid_provider_string)

            encrypted_data_key = EncryptedDataKey(
                key_provider=key_provider, encrypted_data_key=VALUES["encrypted_data_key"]
            )

            # When: serialize_encrypted_data_key
            aws_encryption_sdk.internal.formatting.serialize.serialize_encrypted_data_key(
                encrypted_data_key=encrypted_data_key
            )

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
    def test_GIVEN_required_ec_bytes_WHEN_serialize_header_auth_v1_THEN_aad_has_required_ec_bytes(
        self,
        mock_header_auth_iv,
    ):
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
    def test_GIVEN_required_ec_bytes_WHEN_serialize_header_auth_v2_THEN_aad_has_required_ec_bytes(
        self,
        mock_header_auth_iv,
    ):
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
