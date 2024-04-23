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
"""Unit test suite for aws_encryption_sdk.streaming_client.StreamDecryptor"""
# noqa pylint: disable=too-many-lines
import io

import pytest
from mock import MagicMock, call, patch, sentinel

from aws_encryption_sdk.exceptions import (
    ActionNotAllowedError,
    CustomMaximumValueExceeded,
    MasterKeyProviderError,
    NotSupportedError,
    SerializationError,
)
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy, ContentType, SerializationVersion
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.streaming_client import StreamDecryptor

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


# Check if MPL is installed, and skip tests based on its installation status
# Ideally, this logic would be based on mocking imports and testing logic,
# but doing that introduces errors that cause other tests to fail.
try:
    from aws_encryption_sdk.materials_managers.mpl.cmm import CryptoMaterialsManagerFromMPL
    HAS_MPL = True

except ImportError:
    HAS_MPL = False


class TestStreamDecryptor(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        self.mock_key_provider = MagicMock(__class__=MasterKeyProvider)
        self.mock_materials_manager = MagicMock(__class__=CryptoMaterialsManager)
        self.mock_decrypt_materials = MagicMock(
            data_key=VALUES["data_key_obj"], verification_key=sentinel.verification_key
        )
        self.mock_materials_manager.decrypt_materials.return_value = self.mock_decrypt_materials

        if HAS_MPL:
            self.mock_mpl_materials_manager = MagicMock(__class__=CryptoMaterialsManagerFromMPL)
            self.mock_mpl_materials_manager.decrypt_materials.return_value = self.mock_decrypt_materials

        self.mock_header = MagicMock()
        self.mock_header.version = SerializationVersion.V1
        self.mock_header.algorithm = MagicMock(
            __class__=Algorithm, iv_len=12, is_committing=MagicMock(return_value=False)
        )
        self.mock_header.encrypted_data_keys = set((VALUES["encrypted_data_key_obj"],))
        self.mock_header.encryption_context = sentinel.encryption_context

        self.mock_raw_header = b"some bytes"

        self.mock_input_stream = MagicMock()
        self.mock_input_stream.__class__ = io.IOBase
        self.mock_input_stream.tell.side_effect = (0, 500)

        # Set up deserialize_header patch
        self.mock_deserialize_header_patcher = patch("aws_encryption_sdk.streaming_client.deserialize_header")
        self.mock_deserialize_header = self.mock_deserialize_header_patcher.start()
        self.mock_deserialize_header.return_value = self.mock_header, self.mock_raw_header
        # Set up deserialize_header_auth patch
        self.mock_deserialize_header_auth_patcher = patch("aws_encryption_sdk.streaming_client.deserialize_header_auth")
        self.mock_deserialize_header_auth = self.mock_deserialize_header_auth_patcher.start()
        self.mock_deserialize_header_auth.return_value = sentinel.header_auth
        # Set up validate_header patch
        self.mock_validate_header_patcher = patch("aws_encryption_sdk.streaming_client.validate_header")
        self.mock_validate_header = self.mock_validate_header_patcher.start()
        # Set up deserialize_non_framed_values patch
        self.mock_deserialize_non_framed_values_patcher = patch(
            "aws_encryption_sdk.streaming_client.deserialize_non_framed_values"
        )
        self.mock_deserialize_non_framed_values = self.mock_deserialize_non_framed_values_patcher.start()
        self.mock_deserialize_non_framed_values.return_value = (sentinel.iv, len(VALUES["data_128"]))
        # Set up deserialize_tag_value patch
        self.mock_deserialize_tag_patcher = patch("aws_encryption_sdk.streaming_client.deserialize_tag")
        self.mock_deserialize_tag = self.mock_deserialize_tag_patcher.start()
        self.mock_deserialize_tag.return_value = sentinel.tag
        # Set up get_aad_content_string patch
        self.mock_get_aad_content_string_patcher = patch(
            "aws_encryption_sdk.streaming_client.aws_encryption_sdk.internal.utils.get_aad_content_string"
        )
        self.mock_get_aad_content_string = self.mock_get_aad_content_string_patcher.start()
        self.mock_get_aad_content_string.return_value = sentinel.aad_content_string
        # Set up assemble_content_aad patch
        self.mock_assemble_content_aad_patcher = patch("aws_encryption_sdk.streaming_client.assemble_content_aad")
        self.mock_assemble_content_aad = self.mock_assemble_content_aad_patcher.start()
        self.mock_assemble_content_aad.return_value = sentinel.associated_data
        # Set up Decryptor patch
        self.mock_decryptor_patcher = patch("aws_encryption_sdk.streaming_client.Decryptor")
        self.mock_decryptor = self.mock_decryptor_patcher.start()
        self.mock_decryptor_instance = MagicMock()
        self.mock_decryptor.return_value = self.mock_decryptor_instance
        # Set up deserialize_footer patch
        self.mock_deserialize_footer_patcher = patch("aws_encryption_sdk.streaming_client.deserialize_footer")
        self.mock_deserialize_footer = self.mock_deserialize_footer_patcher.start()
        # Set up deserialize_frame patch
        self.mock_deserialize_frame_patcher = patch("aws_encryption_sdk.streaming_client.deserialize_frame")
        self.mock_deserialize_frame = self.mock_deserialize_frame_patcher.start()
        # Set up decrypt patch
        self.mock_decrypt_patcher = patch("aws_encryption_sdk.streaming_client.decrypt")
        self.mock_decrypt = self.mock_decrypt_patcher.start()
        # Set up hmac.compare_digest patch
        self.mock_compare_digest_patcher = patch("hmac.compare_digest")
        self.mock_compare_digest = self.mock_compare_digest_patcher.start()
        self.mock_compare_digest.return_value = True

        self.mock_commitment_policy = MagicMock(__class__=CommitmentPolicy)

        yield
        # Run tearDown
        self.mock_deserialize_header_patcher.stop()
        self.mock_deserialize_header_auth_patcher.stop()
        self.mock_validate_header_patcher.stop()
        self.mock_deserialize_non_framed_values_patcher.stop()
        self.mock_deserialize_tag_patcher.stop()
        self.mock_get_aad_content_string_patcher.stop()
        self.mock_assemble_content_aad_patcher.stop()
        self.mock_decryptor_patcher.stop()
        self.mock_deserialize_footer_patcher.stop()
        self.mock_deserialize_frame_patcher.stop()
        self.mock_decrypt_patcher.stop()

    def test_init(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        assert test_decryptor.last_sequence_number == 0

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._prep_non_framed")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_header")
    def test_prep_message_framed_message(self, mock_read_header, mock_prep_non_framed):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        mock_read_header.return_value = self.mock_header, sentinel.header_auth
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._prep_message()
        mock_read_header.assert_called_once_with()
        assert test_decryptor._header is self.mock_header
        assert test_decryptor.header_auth is sentinel.header_auth
        assert not mock_prep_non_framed.called
        assert test_decryptor._message_prepped

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._prep_non_framed")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_header")
    def test_prep_message_non_framed_message(self, mock_read_header, mock_prep_non_framed):
        self.mock_header.content_type = ContentType.NO_FRAMING
        mock_read_header.return_value = self.mock_header, sentinel.header_auth
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._prep_message()
        mock_prep_non_framed.assert_called_once_with()

    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    def test_read_header(self, mock_derive_datakey, mock_decrypt_materials_request, mock_verifier):
        mock_verifier_instance = MagicMock()
        mock_verifier.from_key_bytes.return_value = mock_verifier_instance
        ct_stream = io.BytesIO(VALUES["data_128"])
        mock_commitment_policy = MagicMock(__class__=CommitmentPolicy)
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=mock_commitment_policy,
        )
        test_decryptor.source_stream = ct_stream
        test_decryptor._stream_length = len(VALUES["data_128"])

        # Mock: hasattr(self.config, "encryption_context") returns False
        if hasattr(test_decryptor.config, "encryption_context"):
            del test_decryptor.config.encryption_context

        test_header, test_header_auth = test_decryptor._read_header()

        self.mock_deserialize_header.assert_called_once_with(ct_stream, None)
        mock_verifier.from_key_bytes.assert_called_once_with(
            algorithm=self.mock_header.algorithm, key_bytes=sentinel.verification_key
        )
        mock_decrypt_materials_request.assert_called_once_with(
            encrypted_data_keys=self.mock_header.encrypted_data_keys,
            algorithm=self.mock_header.algorithm,
            encryption_context=sentinel.encryption_context,
            commitment_policy=mock_commitment_policy,
        )
        self.mock_materials_manager.decrypt_materials.assert_called_once_with(
            request=mock_decrypt_materials_request.return_value
        )
        mock_verifier_instance.update.assert_called_once_with(self.mock_raw_header)
        self.mock_deserialize_header_auth.assert_called_once_with(
            version=self.mock_header.version,
            stream=ct_stream,
            algorithm=self.mock_header.algorithm,
            verifier=mock_verifier_instance,
        )
        mock_derive_datakey.assert_called_once_with(
            source_key=VALUES["data_key_obj"].data_key,
            algorithm=self.mock_header.algorithm,
            message_id=self.mock_header.message_id,
        )
        assert test_decryptor._derived_data_key is mock_derive_datakey.return_value
        self.mock_validate_header.assert_called_once_with(
            header=self.mock_header,
            header_auth=sentinel.header_auth,
            raw_header=self.mock_raw_header,
            data_key=mock_derive_datakey.return_value,
        )
        assert test_header is self.mock_header
        assert test_header_auth is sentinel.header_auth

    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @patch("aws_encryption_sdk.streaming_client.Verifier")
    # Given: no MPL
    @pytest.mark.skipif(HAS_MPL, reason="Test should only be executed without MPL in installation")
    def test_GIVEN_verification_key_AND_no_mpl_WHEN_read_header_THEN_calls_from_key_bytes(
        self,
        mock_verifier,
        *_,
    ):
        # Given: verification key
        mock_verifier_instance = MagicMock()
        mock_verifier.from_key_bytes.return_value = mock_verifier_instance
        ct_stream = io.BytesIO(VALUES["data_128"])
        mock_commitment_policy = MagicMock(__class__=CommitmentPolicy)
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=mock_commitment_policy,
        )
        test_decryptor.source_stream = ct_stream
        test_decryptor._stream_length = len(VALUES["data_128"])

        # When: read header
        test_decryptor._read_header()

        # Then: calls from_key_bytes
        mock_verifier.from_key_bytes.assert_called_once_with(
            algorithm=self.mock_header.algorithm, key_bytes=sentinel.verification_key
        )

    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @patch("aws_encryption_sdk.streaming_client.Verifier")
    # Given: has MPL
    @pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
    def test_GIVEN_verification_key_AND_has_mpl_AND_not_MPLCMM_WHEN_read_header_THEN_calls_from_key_bytes(
        self,
        mock_verifier,
        *_,
    ):
        # Given: verification key
        mock_verifier_instance = MagicMock()
        mock_verifier.from_key_bytes.return_value = mock_verifier_instance
        ct_stream = io.BytesIO(VALUES["data_128"])
        mock_commitment_policy = MagicMock(__class__=CommitmentPolicy)
        test_decryptor = StreamDecryptor(
            # Given: native CMM
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=mock_commitment_policy,
        )
        test_decryptor.source_stream = ct_stream
        test_decryptor._stream_length = len(VALUES["data_128"])

        # When: read_header
        test_decryptor._read_header()

        # Then: calls from_key_bytess
        mock_verifier.from_key_bytes.assert_called_once_with(
            algorithm=self.mock_header.algorithm, key_bytes=sentinel.verification_key
        )


    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.Verifier")
    # Given: no MPL
    @pytest.mark.skipif(HAS_MPL, reason="Test should only be executed without MPL in installation")
    def test_GIVEN_decrypt_config_has_ec_AND_no_mpl_WHEN_read_header_THEN_raise_TypeError(
        self,
        mock_verifier,
        mock_decrypt_materials_request,
        *_,
    ):

        mock_verifier_instance = MagicMock()
        mock_verifier.from_key_bytes.return_value = mock_verifier_instance
        ct_stream = io.BytesIO(VALUES["data_128"])
        mock_commitment_policy = MagicMock(__class__=CommitmentPolicy)
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=mock_commitment_policy,
        )
        test_decryptor.source_stream = ct_stream
        test_decryptor._stream_length = len(VALUES["data_128"])
        # Given: self.config has "encryption_context"
        # (i.e. encryption context provided on decrypt)
        any_reproduced_ec = {"some": "ec"}
        test_decryptor.config.encryption_context = any_reproduced_ec

        # Then: raise TypeError
        with pytest.raises(TypeError):
            # When: read header
            test_decryptor._read_header()


    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("base64.b64encode")
    # Given: has MPL
    @pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
    def test_GIVEN_verification_key_AND_has_mpl_AND_has_MPLCMM_WHEN_read_header_THEN_calls_from_encoded_point(
        self,
        mock_b64encoding,
        mock_verifier,
        *_,
    ):
        # Given: Verification key
        mock_verifier_instance = MagicMock()
        mock_verifier.from_key_bytes.return_value = mock_verifier_instance
        ct_stream = io.BytesIO(VALUES["data_128"])
        mock_commitment_policy = MagicMock(__class__=CommitmentPolicy)
        test_decryptor = StreamDecryptor(
            # Given: MPL CMM
            materials_manager=self.mock_mpl_materials_manager,
            source=ct_stream,
            commitment_policy=mock_commitment_policy,
        )
        test_decryptor.source_stream = ct_stream
        test_decryptor._stream_length = len(VALUES["data_128"])

        # When: read header
        test_decryptor._read_header()

        # Then: calls from_encoded_point
        mock_verifier.from_encoded_point.assert_called_once_with(
            algorithm=self.mock_header.algorithm, encoded_point=mock_b64encoding()
        )

    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    def test_read_header_frame_too_large(self, mock_derive_datakey):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        self.mock_header.frame_length = 1024
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            max_body_length=10,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.key_provider = self.mock_key_provider
        test_decryptor.source_stream = ct_stream
        test_decryptor._stream_length = len(VALUES["data_128"])
        with pytest.raises(CustomMaximumValueExceeded) as excinfo:
            test_decryptor._read_header()
        excinfo.match(
            "Frame Size in header found larger than custom value: {found} > {custom}".format(found=1024, custom=10)
        )

    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    def test_read_header_no_verifier(self, mock_derive_datakey, mock_decrypt_materials_request, mock_verifier):
        self.mock_materials_manager.decrypt_materials.return_value = MagicMock(
            data_key=VALUES["data_key_obj"], verification_key=None
        )
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.key_provider = self.mock_key_provider
        test_decryptor.source_stream = self.mock_input_stream
        test_decryptor._stream_length = len(VALUES["data_128"])
        test_decryptor._read_header()
        assert test_decryptor.verifier is None

    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @pytest.mark.parametrize(
        "policy",
        (
            CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ),
    )
    def test_commitment_committing_algorithm_policy_allows_check_passes(
        self, mock_derive_datakey, mock_decrypt_materials_request, mock_verifier, policy
    ):
        """Verifies that when the commitment check passes for a committing algorithm on decrypt, we successfully
        read the header."""
        self.mock_header.algorithm = MagicMock(
            __class__=Algorithm, iv_len=12, is_committing=MagicMock(return_value=True)
        )

        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=policy,
        )
        test_decryptor.key_provider = self.mock_key_provider
        test_decryptor.source_stream = self.mock_input_stream
        test_decryptor._stream_length = len(VALUES["data_128"])
        test_decryptor._read_header()
        self.mock_deserialize_header.assert_called_once_with(self.mock_input_stream, None)

    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    def test_commitment_committing_algorithm_policy_allows_check_fails(
        self, mock_derive_datakey, mock_decrypt_materials_request, mock_verifier
    ):
        """Verifies that when the commitment check fails for a committing algorithm on decrypt, we emit the correct
        exception."""
        self.mock_compare_digest.return_value = False
        self.mock_header.algorithm = MagicMock(
            __class__=Algorithm, iv_len=12, is_committing=MagicMock(return_value=True)
        )

        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        )

        with pytest.raises(MasterKeyProviderError) as excinfo:
            test_decryptor._read_header()
        excinfo.match("Key commitment validation failed")

    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @pytest.mark.parametrize(
        "policy", (CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
    )
    def test_commitment_uncommitting_algorithm_policy_allows(
        self, mock_derive_datakey, mock_decrypt_materials_request, mock_verifier, policy
    ):
        """Verifies that we can successfully read the header on a message encrypted with an algorithm that
        does not provide commitment when the policy allows it."""
        self.mock_header.algorithm = MagicMock(
            __class__=Algorithm, iv_len=12, is_committing=MagicMock(return_value=False)
        )

        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=policy,
        )
        test_decryptor._read_header()
        self.mock_deserialize_header.assert_called_once_with(self.mock_input_stream, None)
        self.mock_compare_digest.assert_not_called()

    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    def test_commitment_uncommitting_algorithm_policy_requires_encrypt(
        self, mock_derive_datakey, mock_decrypt_materials_request, mock_verifier
    ):
        """Verifies that we emit the correct exception on a message encrypted with an algorithm that
        does not provide commitment when the policy requires commitment."""
        self.mock_header.algorithm = MagicMock(
            __class__=Algorithm, iv_len=12, is_committing=MagicMock(return_value=False)
        )

        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        with pytest.raises(ActionNotAllowedError) as excinfo:
            test_decryptor._read_header()
        excinfo.match("Configuration conflict. Cannot decrypt due to .* requiring only committed messages")

    def test_prep_non_framed_content_length_too_large(self):
        self.mock_header.content_type = ContentType.NO_FRAMING
        self.mock_header.frame_length = 1024
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            max_body_length=len(VALUES["data_128"]) // 2,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._header = self.mock_header
        test_decryptor.verifier = sentinel.verifier
        mock_data_key = MagicMock()
        test_decryptor.data_key = mock_data_key

        with pytest.raises(CustomMaximumValueExceeded) as excinfo:
            test_decryptor._prep_non_framed()
        excinfo.match(
            "Non-framed message content length found larger than custom value: {found} > {custom}".format(
                found=len(VALUES["data_128"]), custom=len(VALUES["data_128"]) // 2
            )
        )

    def test_prep_non_framed(self):
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._header = self.mock_header
        test_decryptor.verifier = sentinel.verifier
        test_decryptor._derived_data_key = sentinel.derived_data_key

        test_decryptor._prep_non_framed()

        self.mock_deserialize_non_framed_values.assert_called_once_with(
            stream=test_decryptor.source_stream, header=self.mock_header, verifier=sentinel.verifier
        )
        assert test_decryptor.body_length == len(VALUES["data_128"])
        assert test_decryptor._body_start == self.mock_header.algorithm.iv_len + 8
        assert test_decryptor._body_end == self.mock_header.algorithm.iv_len + 8 + len(VALUES["data_128"])

    def test_read_bytes_from_non_framed(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.body_length = len(VALUES["data_128"])
        test_decryptor.decryptor = self.mock_decryptor_instance
        test_decryptor._header = self.mock_header
        test_decryptor.verifier = MagicMock()
        test_decryptor._derived_data_key = sentinel.derived_data_key
        test_decryptor._unframed_body_iv = sentinel.unframed_body_iv
        self.mock_decryptor_instance.update.return_value = b"1234"
        self.mock_decryptor_instance.finalize.return_value = b"5678"

        test = test_decryptor._read_bytes_from_non_framed_body(5)

        self.mock_deserialize_tag.assert_called_once_with(
            stream=test_decryptor.source_stream, header=test_decryptor._header, verifier=test_decryptor.verifier
        )
        self.mock_get_aad_content_string.assert_called_once_with(
            content_type=self.mock_header.content_type, is_final_frame=True
        )
        self.mock_assemble_content_aad.assert_called_once_with(
            message_id=self.mock_header.message_id,
            aad_content_string=sentinel.aad_content_string,
            seq_num=1,
            length=len(VALUES["data_128"]),
        )
        self.mock_decryptor.assert_called_once_with(
            algorithm=self.mock_header.algorithm,
            key=sentinel.derived_data_key,
            associated_data=sentinel.associated_data,
            iv=sentinel.unframed_body_iv,
            tag=sentinel.tag,
        )
        assert test_decryptor.decryptor is self.mock_decryptor_instance
        test_decryptor.verifier.update.assert_called_once_with(VALUES["data_128"])
        self.mock_decryptor_instance.update.assert_called_once_with(VALUES["data_128"])
        assert test == b"12345678"

    def test_read_bytes_from_non_framed_message_body_too_small(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.body_length = len(VALUES["data_128"] * 2)
        test_decryptor._header = self.mock_header
        with pytest.raises(SerializationError) as excinfo:
            test_decryptor._read_bytes_from_non_framed_body(1)
        excinfo.match("Total message body contents less than specified in body description")

    def test_read_bytes_from_non_framed_no_verifier(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.body_length = len(VALUES["data_128"])
        test_decryptor.decryptor = self.mock_decryptor_instance
        test_decryptor._header = self.mock_header
        test_decryptor._derived_data_key = sentinel.derived_data_key
        test_decryptor._unframed_body_iv = sentinel.unframed_body_iv
        test_decryptor.verifier = None
        self.mock_decryptor_instance.update.return_value = b"1234"
        test_decryptor._read_bytes_from_non_framed_body(5)

    def test_read_bytes_from_non_framed_finalize(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.body_length = len(VALUES["data_128"])
        test_decryptor.decryptor = self.mock_decryptor_instance
        test_decryptor.verifier = MagicMock()
        test_decryptor._header = self.mock_header
        test_decryptor._derived_data_key = sentinel.derived_data_key
        test_decryptor._unframed_body_iv = sentinel.unframed_body_iv
        self.mock_decryptor_instance.update.return_value = b"1234"
        self.mock_decryptor_instance.finalize.return_value = b"5678"

        test = test_decryptor._read_bytes_from_non_framed_body(len(VALUES["data_128"]) + 1)

        test_decryptor.verifier.update.assert_called_once_with(VALUES["data_128"])
        self.mock_decryptor_instance.update.assert_called_once_with(VALUES["data_128"])
        self.mock_deserialize_footer.assert_called_once_with(
            stream=test_decryptor.source_stream, verifier=test_decryptor.verifier
        )
        assert test == b"12345678"

    def test_read_bytes_from_framed_body_multi_frame_finalize(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.verifier = MagicMock()
        test_decryptor.data_key = MagicMock()
        test_decryptor._header = self.mock_header
        test_decryptor._derived_data_key = sentinel.derived_data_key
        frame_data_1 = MagicMock()
        frame_data_1.sequence_number = 1
        frame_data_1.final_frame = False
        frame_data_1.ciphertext = b"qwer"
        frame_data_2 = MagicMock()
        frame_data_2.sequence_number = 2
        frame_data_2.final_frame = False
        frame_data_2.ciphertext = b"asdfg"
        frame_data_3 = MagicMock()
        frame_data_3.sequence_number = 3
        frame_data_3.final_frame = False
        frame_data_3.ciphertext = b"zxcvbn"
        frame_data_4 = MagicMock()
        frame_data_4.sequence_number = 4
        frame_data_4.final_frame = True
        frame_data_4.ciphertext = b"yuiohjk"
        self.mock_deserialize_frame.side_effect = (
            (frame_data_1, False),
            (frame_data_2, False),
            (frame_data_3, False),
            (frame_data_4, True),
        )
        self.mock_get_aad_content_string.side_effect = (
            sentinel.aad_content_string_1,
            sentinel.aad_content_string_2,
            sentinel.aad_content_string_3,
            sentinel.aad_content_string_4,
        )
        self.mock_assemble_content_aad.side_effect = (
            sentinel.associated_data_1,
            sentinel.associated_data_2,
            sentinel.associated_data_3,
            sentinel.associated_data_4,
        )
        self.mock_decrypt.side_effect = (b"123", b"456", b"789", b"0-=")

        test = test_decryptor._read_bytes_from_framed_body(12)

        self.mock_deserialize_frame.assert_has_calls(
            calls=(
                call(
                    stream=test_decryptor.source_stream, header=test_decryptor._header, verifier=test_decryptor.verifier
                ),
                call(
                    stream=test_decryptor.source_stream, header=test_decryptor._header, verifier=test_decryptor.verifier
                ),
                call(
                    stream=test_decryptor.source_stream, header=test_decryptor._header, verifier=test_decryptor.verifier
                ),
                call(
                    stream=test_decryptor.source_stream, header=test_decryptor._header, verifier=test_decryptor.verifier
                ),
            ),
            any_order=False,
        )
        self.mock_get_aad_content_string.assert_has_calls(
            calls=(
                call(content_type=test_decryptor._header.content_type, is_final_frame=False),
                call(content_type=test_decryptor._header.content_type, is_final_frame=False),
                call(content_type=test_decryptor._header.content_type, is_final_frame=False),
                call(content_type=test_decryptor._header.content_type, is_final_frame=True),
            ),
            any_order=False,
        )
        self.mock_assemble_content_aad.assert_has_calls(
            calls=(
                call(
                    message_id=test_decryptor._header.message_id,
                    aad_content_string=sentinel.aad_content_string_1,
                    seq_num=1,
                    length=4,
                ),
                call(
                    message_id=test_decryptor._header.message_id,
                    aad_content_string=sentinel.aad_content_string_2,
                    seq_num=2,
                    length=5,
                ),
                call(
                    message_id=test_decryptor._header.message_id,
                    aad_content_string=sentinel.aad_content_string_3,
                    seq_num=3,
                    length=6,
                ),
                call(
                    message_id=test_decryptor._header.message_id,
                    aad_content_string=sentinel.aad_content_string_4,
                    seq_num=4,
                    length=7,
                ),
            ),
            any_order=False,
        )
        self.mock_decrypt.assert_has_calls(
            calls=(
                call(
                    algorithm=test_decryptor._header.algorithm,
                    key=sentinel.derived_data_key,
                    encrypted_data=frame_data_1,
                    associated_data=sentinel.associated_data_1,
                ),
                call(
                    algorithm=test_decryptor._header.algorithm,
                    key=sentinel.derived_data_key,
                    encrypted_data=frame_data_2,
                    associated_data=sentinel.associated_data_2,
                ),
                call(
                    algorithm=test_decryptor._header.algorithm,
                    key=sentinel.derived_data_key,
                    encrypted_data=frame_data_3,
                    associated_data=sentinel.associated_data_3,
                ),
                call(
                    algorithm=test_decryptor._header.algorithm,
                    key=sentinel.derived_data_key,
                    encrypted_data=frame_data_4,
                    associated_data=sentinel.associated_data_4,
                ),
            ),
            any_order=False,
        )
        self.mock_deserialize_footer.assert_called_once_with(
            stream=test_decryptor.source_stream, verifier=test_decryptor.verifier
        )
        assert test == b"1234567890-="

    def test_read_bytes_from_framed_body_single_frame(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.verifier = MagicMock()
        test_decryptor.data_key = MagicMock()
        test_decryptor._header = self.mock_header
        test_decryptor._derived_data_key = sentinel.derived_data_key
        frame_data = MagicMock()
        frame_data.sequence_number = 1
        frame_data.final_frame = False
        frame_data.ciphertext = b"asdfzxcv"
        self.mock_deserialize_frame.return_value = (frame_data, False)
        self.mock_get_aad_content_string.return_value = sentinel.aad_content_string
        self.mock_assemble_content_aad.return_value = sentinel.associated_data
        self.mock_decrypt.return_value = b"1234"

        test = test_decryptor._read_bytes_from_framed_body(4)

        self.mock_deserialize_frame.assert_called_once_with(
            stream=test_decryptor.source_stream, header=test_decryptor._header, verifier=test_decryptor.verifier
        )
        assert not self.mock_deserialize_footer.called
        assert test == b"1234"

    def test_read_bytes_from_framed_body_bad_sequence_number(self):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.verifier = MagicMock()
        test_decryptor._header = self.mock_header
        frame_data = MagicMock()
        frame_data.sequence_number = 5
        frame_data.final_frame = False
        frame_data.ciphertext = b"asdfzxcv"
        self.mock_deserialize_frame.return_value = (frame_data, False)
        with pytest.raises(SerializationError) as excinfo:
            test_decryptor._read_bytes_from_framed_body(4)
        excinfo.match("Malformed message: frames out of order")

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_non_framed_body")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_framed_body")
    def test_read_bytes_completed(self, mock_read_frame, mock_read_block):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.footer = None
        test_decryptor._read_bytes(5)
        assert not mock_read_frame.called
        assert not mock_read_block.called

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_non_framed_body")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_framed_body")
    def test_read_bytes_no_read_required(self, mock_read_frame, mock_read_block):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.output_buffer = b"1234567"
        test_decryptor._read_bytes(5)
        assert not mock_read_frame.called
        assert not mock_read_block.called

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_non_framed_body")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_framed_body")
    def test_read_bytes_framed(self, mock_read_frame, mock_read_block):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._header = MagicMock()
        test_decryptor._header.content_type = ContentType.FRAMED_DATA
        test_decryptor._read_bytes(5)
        mock_read_frame.assert_called_once_with(5)
        assert not mock_read_block.called

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_non_framed_body")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_framed_body")
    def test_read_bytes_non_framed(self, mock_read_frame, mock_read_block):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._header = MagicMock()
        test_decryptor._header.content_type = ContentType.NO_FRAMING
        test_decryptor._read_bytes(5)
        mock_read_block.assert_called_once_with(5)
        assert not mock_read_frame.called

    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_non_framed_body")
    @patch("aws_encryption_sdk.streaming_client.StreamDecryptor._read_bytes_from_framed_body")
    def test_read_bytes_unknown(self, mock_read_frame, mock_read_block):
        ct_stream = io.BytesIO(VALUES["data_128"])
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=ct_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._header = MagicMock()
        test_decryptor._header.content_type = None
        with pytest.raises(NotSupportedError) as excinfo:
            test_decryptor._read_bytes(5)
        excinfo.match("Unsupported content type")

    @patch("aws_encryption_sdk.streaming_client._EncryptionStream.close")
    def test_close(self, mock_close):
        self.mock_header.content_type = ContentType.NO_FRAMING
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor.footer = sentinel.footer
        test_decryptor.data_key = VALUES["data_key_obj"]
        test_decryptor.close()
        mock_close.assert_called_once_with()

    @patch("aws_encryption_sdk.streaming_client._EncryptionStream.close")
    def test_close_no_footer(self, mock_close):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        with pytest.raises(SerializationError) as excinfo:
            test_decryptor.close()
        excinfo.match("Footer not read")

    @patch("aws_encryption_sdk.streaming_client.validate_header")
    def test_GIVEN_does_not_have_required_EC_WHEN_validate_parsed_header_THEN_validate_header(
        self,
        mock_validate_header
    ):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._derived_data_key = sentinel.derived_data_key
        # Given: test_decryptor does not have _required_encryption_context attribute
        # When: _validate_parsed_header
        test_decryptor._validate_parsed_header(
            header=self.mock_header,
            header_auth=sentinel.header_auth,
            raw_header=self.mock_raw_header
        )
        # Then: validate_header
        mock_validate_header.assert_called_once_with(
            header=self.mock_header,
            header_auth=sentinel.header_auth,
            raw_header=self.mock_raw_header,
            data_key=sentinel.derived_data_key,
        )

    @patch("aws_encryption_sdk.internal.formatting.encryption_context.serialize_encryption_context")
    @patch("aws_encryption_sdk.streaming_client.validate_header")
    def test_GIVEN_has_required_EC_WHEN_validate_parsed_header_THEN_validate_header_with_serialized_required_EC(
        self,
        mock_validate_header,
        mock_serialize_encryption_context,
    ):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )
        test_decryptor._derived_data_key = sentinel.derived_data_key
        # Given: test_decryptor has _required_encryption_context attribute
        mock_required_ec = MagicMock(__class__=dict)
        test_decryptor._required_encryption_context = mock_required_ec
        mock_serialized_required_ec = MagicMock(__class__=bytes)
        mock_serialize_encryption_context.return_value = mock_serialized_required_ec
        # When: _validate_parsed_header
        test_decryptor._validate_parsed_header(
            header=self.mock_header,
            header_auth=sentinel.header_auth,
            raw_header=self.mock_raw_header
        )
        # Then: call validate_header with serialized required EC
        mock_validate_header.assert_called_once_with(
            header=self.mock_header,
            header_auth=sentinel.header_auth,
            raw_header=self.mock_raw_header + mock_serialized_required_ec,
            data_key=sentinel.derived_data_key,
        )

    # Given: has MPL
    @pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
    def test_GIVEN_has_MPL_AND_config_has_EC_WHEN_create_decrypt_materials_request_THEN_provide_reproduced_EC(
        self,
    ):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_mpl_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )

        # Given: StreamDecryptor.config has encryption_context attribute
        mock_reproduced_encryption_context = MagicMock(__class__=dict)
        test_decryptor.config.encryption_context = mock_reproduced_encryption_context
        # Type checking on header encryption context seems to require concrete instance,
        # neither MagicMock nor sentinel value work
        self.mock_header.encryption_context = {"some_key_to_pass_type_validation": "some_value"}

        # When: _create_decrypt_materials_request
        output = test_decryptor._create_decrypt_materials_request(
            header=self.mock_header,
        )

        # Then: decrypt_materials_request has reproduced_encryption_context attribute
        assert hasattr(output, "reproduced_encryption_context")
        assert output.reproduced_encryption_context == mock_reproduced_encryption_context

    def test_GIVEN_config_does_not_have_EC_WHEN_create_decrypt_materials_request_THEN_request_does_not_have_reproduced_EC(  # noqa pylint: disable=line-too-long
        self,
    ):
        self.mock_header.content_type = ContentType.FRAMED_DATA
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )

        # Given: StreamDecryptor.config does not have an encryption_context attribute
        del test_decryptor.config.encryption_context
        # Type checking on header encryption context seems to require concrete instance,
        # neither MagicMock nor sentinel value work
        self.mock_header.encryption_context = {"some_key_to_pass_type_validation": "some_value"}

        # When: _create_decrypt_materials_request
        output = test_decryptor._create_decrypt_materials_request(
            header=self.mock_header,
        )

        # Then: decrypt_materials_request.reproduced_encryption_context is None
        assert output.reproduced_encryption_context is None

    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.Verifier")
    @pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
    def test_GIVEN_materials_has_no_required_encryption_context_keys_attr_WHEN_read_header_THEN_required_EC_is_None(
        self,
        mock_verifier,
        *_
    ):

        mock_verifier_instance = MagicMock()
        mock_verifier.from_key_bytes.return_value = mock_verifier_instance

        self.mock_header.content_type = ContentType.FRAMED_DATA
        test_decryptor = StreamDecryptor(
            materials_manager=self.mock_materials_manager,
            source=self.mock_input_stream,
            commitment_policy=self.mock_commitment_policy,
        )

        # Given: decryption_materials does not have a required_encryption_context_keys attribute
        del self.mock_decrypt_materials.required_encryption_context_keys

        # When: _read_header
        test_decryptor._read_header()

        # Then: StreamDecryptor._required_encryption_context is None
        assert test_decryptor._required_encryption_context is None

    @patch("aws_encryption_sdk.streaming_client.derive_data_encryption_key")
    @patch("aws_encryption_sdk.streaming_client.DecryptionMaterialsRequest")
    @patch("aws_encryption_sdk.streaming_client.Verifier")
    # Given: has MPL
    @pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
    def test_GIVEN_materials_has_required_encryption_context_keys_attr_WHEN_read_header_THEN_creates_correct_required_EC(  # noqa pylint: disable=line-too-long
        self,
        mock_verifier,
        *_
    ):
        required_encryption_context_keys_values = [
            # Case of empty encryption context list is not allowed;
            # if a list is provided, it must be non-empty.
            # The MPL enforces this behavior on construction.
            ["one_key"],
            ["one_key", "two_key"],
            ["one_key", "two_key", "red_key"],
            ["one_key", "two_key", "red_key", "blue_key"],
        ]

        encryption_context_values = [
            {},
            {"one_key": "some_value"},
            {
                "one_key": "some_value",
                "two_key": "some_other_value",
            },
            {
                "one_key": "some_value",
                "two_key": "some_other_value",
                "red_key": "some_red_value",
            },
            {
                "one_key": "some_value",
                "two_key": "some_other_value",
                "red_key": "some_red_value",
                "blue_key": "some_blue_value",
            }
        ]

        for required_encryption_context_keys in required_encryption_context_keys_values:

            # Given: decryption_materials has required_encryption_context_keys
            self.mock_decrypt_materials.required_encryption_context_keys = \
                required_encryption_context_keys

            for encryption_context in encryption_context_values:

                self.mock_decrypt_materials.encryption_context = encryption_context

                mock_verifier_instance = MagicMock()
                mock_verifier.from_key_bytes.return_value = mock_verifier_instance

                self.mock_header.content_type = ContentType.FRAMED_DATA
                test_decryptor = StreamDecryptor(
                    materials_manager=self.mock_materials_manager,
                    source=self.mock_input_stream,
                    commitment_policy=self.mock_commitment_policy,
                )

                # When: _read_header
                test_decryptor._read_header()

                # Then: Assert correctness of partitioned EC
                for k, v in encryption_context.items():
                    # If a key is in required_encryption_context_keys, then ...
                    if k in required_encryption_context_keys:
                        # ... its EC is in the StreamEncryptor._required_encryption_context
                        assert k in test_decryptor._required_encryption_context
                        assert test_decryptor._required_encryption_context[k] == v
                    # If a key is NOT in required_encryption_context_keys, then ...
                    else:
                        # ... its EC is NOT in the StreamEncryptor._required_encryption_context
                        assert k not in test_decryptor._required_encryption_context
