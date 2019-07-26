# coding: utf-8
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
"""Test suite for aws_encryption_sdk.internal.utils"""
import io

import pytest
from mock import MagicMock, patch, sentinel

from cryptography.hazmat.backends import default_backend
import aws_encryption_sdk.identifiers
import aws_encryption_sdk.internal.utils
from aws_encryption_sdk.exceptions import InvalidDataKeyError, SerializationError, UnknownIdentityError
from aws_encryption_sdk.internal.defaults import MAX_FRAME_SIZE, MESSAGE_ID_LENGTH
from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag
from aws_encryption_sdk.keyring.base import EncryptedDataKey, Keyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import KeyringTrace, MasterKeyInfo, RawDataKey, DataKey

from .test_values import VALUES
from .unit_test_utils import assert_prepped_stream_identity

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_SIGNING_KEY = b"aws-crypto-public-key"
_DATA_KEY = (
    b"\x00\xfa\x8c\xdd\x08Au\xc6\x92_4\xc5\xfb\x90\xaf\x8f\xa1D\xaf\xcc\xd25" b"\xa8\x0b\x0b\x16\x92\x91W\x01\xb7\x84"
)

_PUBLIC_EXPONENT = 65537
_KEY_SIZE = 2048
_BACKEND = default_backend()

_ENCRYPTED_DATA_KEY_AES = EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id='Random Raw Keys',
                key_info=b'5325b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80'
                         b'\x00\x00\x00\x0c\xc7\xd5d\xc9\xc5\xf21\x8d\x8b\xf9H'
                         b'\xbb'),
            encrypted_data_key=b'\xf3+\x15n\xe6`\xbe\xfe\xf0\x9e1\xe5\x9b'
                               b'\xaf\xfe\xdaT\xbb\x17\x14\xfd} o\xdd\xf1'
                               b'\xbc\xe1C\xa5J\xd8\xc7\x15\xc2\x90t=\xb9'
                               b'\xfd;\x94lTu/6\xfe'

)

_ENCRYPTED_DATA_KEY_RSA = EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id='Random Raw Keys',
                key_info=_KEY_ID),
            encrypted_data_key=b'\xf3+\x15n\xe6`\xbe\xfe\xf0\x9e1\xe5\x9b'
                               b'\xaf\xfe\xdaT\xbb\x17\x14\xfd} o\xdd\xf1'
                               b'\xbc\xe1C\xa5J\xd8\xc7\x15\xc2\x90t=\xb9'
                               b'\xfd;\x94lTu/6\xfe'

)


_ENCRYPTION_MATERIALS_WITH_DATA_KEY = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    data_encryption_key=RawDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"5430b043-5843-4629-869c-64794af77ada"),
        data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
    ),
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
    keyring_trace=[
        KeyringTrace(
            wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"5430b043-5843-4629-869c-64794af77ada"),
            flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
        )
    ],
)

_ENCRYPTION_MATERIALS_WITH_ENCRYPTED_DATA_KEY_AES = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    data_encryption_key=RawDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
    ),
    encrypted_data_keys=[
        _ENCRYPTED_DATA_KEY_AES
    ],
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
    keyring_trace=[
        KeyringTrace(
            wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY},
        )
    ],
)

_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
)

_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY = DecryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    verification_key=b"ex_verification_key",
    encryption_context=_ENCRYPTION_CONTEXT,
)

_DECRYPTION_MATERIALS_WITH_DATA_KEY = DecryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    data_encryption_key=RawDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"5430b043-5843-4629-869c-64794af77ada"),
        data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
    ),
    encryption_context=_ENCRYPTION_CONTEXT,
    verification_key=b"ex_verification_key",
    keyring_trace=[
        KeyringTrace(
            wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=b"5430b043-5843-4629-869c-64794af77ada"),
            flags={KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY},
        )
    ],
)


def test_prep_stream_data_passthrough():
    test = aws_encryption_sdk.internal.utils.prep_stream_data(io.BytesIO(b"some data"))

    assert_prepped_stream_identity(test, io.BytesIO)


@pytest.mark.parametrize("source", (u"some unicode data ловие", b"\x00\x01\x02"))
def test_prep_stream_data_wrap(source):
    test = aws_encryption_sdk.internal.utils.prep_stream_data(source)

    assert_prepped_stream_identity(test, io.BytesIO)


class IdentityKeyring(Keyring):
    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        return decryption_materials


class TestUtils(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        # Set up mock key provider and keys
        self.mock_key_provider_1 = MasterKeyInfo(provider_id="adijoasijfoi", key_info=b"asoiwef8q34")
        self.mock_raw_data_key_1_bytes = b"asioufhaw9eruhtg"
        self.mock_generated_data_key_1_bytes = b"df2hj9348r9824"
        self.mock_encrypted_data_key_1_bytes = b"asioufhaw9eruhtg"
        self.mock_raw_data_key_1 = RawDataKey(
            key_provider=self.mock_key_provider_1, data_key=self.mock_raw_data_key_1_bytes
        )
        self.mock_generated_data_key_1 = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_generated_data_key_1_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes,
        )
        self.mock_encrypted_data_key_1 = EncryptedDataKey(
            key_provider=self.mock_key_provider_1, encrypted_data_key=self.mock_encrypted_data_key_1_bytes
        )
        self.mock_key_provider_2 = MasterKeyInfo(provider_id="9heui5349gh38", key_info=b"fj98349yhsfd")
        self.mock_raw_data_key_2_bytes = b"ane4856ht9w87y5"
        self.mock_generated_data_key_2_bytes = b"fih94587ty3t58yh5tg"
        self.mock_encrypted_data_key_2_bytes = b"ane4856ht9w87y5"
        self.mock_generated_data_key_2 = DataKey(
            key_provider=self.mock_key_provider_2,
            data_key=self.mock_generated_data_key_2_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_2_bytes,
        )
        self.mock_encrypted_data_key_2 = EncryptedDataKey(
            key_provider=self.mock_key_provider_2, encrypted_data_key=self.mock_encrypted_data_key_2_bytes
        )
        self.mock_key_provider_3 = MasterKeyInfo(provider_id="sdfiwehjf9384u", key_info=b"evih5874yh587tyhu5")
        self.mock_raw_data_key_3_bytes = b"f839u459t83uh5rugh"
        self.mock_generated_data_key_3_bytes = b"sjhfuiehw498gfyu34098upoi"
        self.mock_encrypted_data_key_3_bytes = b"f839u459t83uh5rugh"
        self.mock_generated_data_key_3 = DataKey(
            key_provider=self.mock_key_provider_3,
            data_key=self.mock_generated_data_key_3_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_3_bytes,
        )
        self.mock_encrypted_data_key_3 = EncryptedDataKey(
            key_provider=self.mock_key_provider_3, encrypted_data_key=self.mock_encrypted_data_key_3_bytes
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
            [self.mock_master_key_1, self.mock_master_key_2, self.mock_master_key_3],
        )
        self.mock_decrypted_data_key_bytes = b"sehf98w34y987y9uierfh"
        self.mock_encrypted_data_key_bytes = b"sdhf4w398hfwea98ihfr0w8"
        self.mock_data_key = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_decrypted_data_key_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_bytes,
        )
        self.mock_encrypted_data_key = EncryptedDataKey(
            key_provider=self.mock_key_provider_1, encrypted_data_key=self.mock_encrypted_data_key_bytes
        )
        self.mock_decrypted_data_key = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_decrypted_data_key_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes,
        )
        self.mock_master_key_provider.decrypt_data_key.return_value = self.mock_decrypted_data_key
        # Set up mock algorithm
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.encryption_algorithm.block_size = VALUES["block_size"]
        self.mock_algorithm.algorithm_id = VALUES["algorithm_id"]
        self.mock_algorithm.iv_len = VALUES["iv_len"]
        self.mock_algorithm.tag_len = self.mock_algorithm.auth_len = VALUES["tag_len"]
        self.mock_algorithm.data_key_len = VALUES["data_key_len"]
        # Set up mock objects
        self.mock_bad_encrypted_key = MagicMock()
        self.mock_bad_encrypted_key.encrypted_data_key = sentinel.bad_encrypted_data_key
        self.mock_aws_encryption_sdk = MagicMock()
        # Set up os.urandom patch
        self.mock_urandom_patcher = patch("aws_encryption_sdk.internal.utils.os.urandom")
        self.mock_urandom = self.mock_urandom_patcher.start()
        self.mock_urandom.return_value = sentinel.random
        # Set up KMSClient patch
        self.mock_aws_encryption_sdk_instance = MagicMock()
        self.mock_aws_encryption_sdk_instance.generate_data_key.return_value = (
            VALUES["data_key"],
            VALUES["encrypted_data_key"],
        )
        self.mock_aws_encryption_sdk_instance.decrypt.return_value = VALUES["data_key"]
        self.mock_aws_encryption_sdk_instance.encrypt.return_value = VALUES["encrypted_data_key"]
        yield
        # Run tearDown
        self.mock_urandom_patcher.stop()

    def test_validate_frame_length_negative_frame_length(self):
        """Validate that the validate_frame_length function
            behaves as expected when supplied with a
            negative frame length.
        """
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.utils.validate_frame_length(frame_length=-1, algorithm=self.mock_algorithm)
        excinfo.match("Frame size must be a non-negative multiple of the block size of the crypto algorithm: *")

    def test_validate_frame_length_invalid_frame_length(self):
        """Validate that the validate_frame_length function
            behaves as expected when supplied with an
            invalid frame length.
        """
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.utils.validate_frame_length(frame_length=1, algorithm=self.mock_algorithm)
        excinfo.match("Frame size must be a non-negative multiple of the block size of the crypto algorithm: *")

    def test_validate_frame_length_too_large(self):
        """Validate that the validate_frame_length function
            behaves as expected when supplied with a
            frame length which is too large.
        """
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.utils.validate_frame_length(
                frame_length=MAX_FRAME_SIZE + 1, algorithm=self.mock_algorithm
            )
        excinfo.match("Frame size too large: *")

    def test_message_id(self):
        """Validate that the message_id function behaves as expected."""
        test = aws_encryption_sdk.internal.utils.message_id()
        self.mock_urandom.assert_called_once_with(MESSAGE_ID_LENGTH)
        assert test == sentinel.random

    def test_get_aad_content_string_no_framing(self):
        """Validate that the get_aad_content_string function behaves
            as expected when called with NO_FRAMING.
        """
        test = aws_encryption_sdk.internal.utils.get_aad_content_string(
            aws_encryption_sdk.identifiers.ContentType.NO_FRAMING, False
        )
        assert test == aws_encryption_sdk.identifiers.ContentAADString.NON_FRAMED_STRING_ID

    def test_get_aad_content_string_framing(self):
        """Validate that the get_aad_content_string function behaves
            as expected when called with FRAMED_DATA.
        """
        test = aws_encryption_sdk.internal.utils.get_aad_content_string(
            aws_encryption_sdk.identifiers.ContentType.FRAMED_DATA, False
        )
        assert test == aws_encryption_sdk.identifiers.ContentAADString.FRAME_STRING_ID

    def test_get_aad_content_string_framing_final_frame(self):
        """Validate that the get_aad_content_string function behaves as
            expected when called with FRAMED_DATA and final frame.
        """
        test = aws_encryption_sdk.internal.utils.get_aad_content_string(
            aws_encryption_sdk.identifiers.ContentType.FRAMED_DATA, True
        )
        assert test == aws_encryption_sdk.identifiers.ContentAADString.FINAL_FRAME_STRING_ID

    def test_get_aad_content_string_framing_bad_type(self):
        """Validate that the get_aad_content_string function behaves as
            expected when called with an unknown content type.
        """
        with pytest.raises(UnknownIdentityError) as excinfo:
            aws_encryption_sdk.internal.utils.get_aad_content_string(-1, False)
        excinfo.match("Unhandled content type")

    def test_prepare_data_keys(self):
        mock_encryption_dk = DataKey(
            key_provider=self.mock_key_provider_1,
            data_key=self.mock_raw_data_key_1_bytes,
            encrypted_data_key=self.mock_encrypted_data_key_1_bytes,
        )
        mock_primary_mk = MagicMock()
        mock_primary_mk.generate_data_key.return_value = mock_encryption_dk
        mock_mk_1 = MagicMock()
        mock_mk_1.encrypt_data_key.return_value = sentinel.encrypted_data_key_1
        mock_mk_2 = MagicMock()
        mock_mk_2.encrypt_data_key.return_value = sentinel.encrypted_data_key_2
        test_data_encryption_key, test_encrypted_data_keys = aws_encryption_sdk.internal.utils.prepare_data_keys(
            primary_master_key=mock_primary_mk,
            master_keys=[mock_primary_mk, mock_mk_1, mock_mk_2],
            algorithm=sentinel.algorithm,
            encryption_context=sentinel.encryption_context,
        )
        mock_primary_mk.generate_data_key.assert_called_once_with(sentinel.algorithm, sentinel.encryption_context)
        assert not mock_primary_mk.encrypt_data_key.called
        mock_mk_1.encrypt_data_key.assert_called_once_with(
            data_key=mock_encryption_dk, algorithm=sentinel.algorithm, encryption_context=sentinel.encryption_context
        )
        mock_mk_2.encrypt_data_key.assert_called_once_with(
            data_key=mock_encryption_dk, algorithm=sentinel.algorithm, encryption_context=sentinel.encryption_context
        )
        mock_encrypted_data_encryption_key = EncryptedDataKey(
            key_provider=self.mock_key_provider_1, encrypted_data_key=self.mock_encrypted_data_key_1_bytes
        )
        assert test_data_encryption_key is mock_encryption_dk
        assert test_encrypted_data_keys == set(
            [mock_encrypted_data_encryption_key, sentinel.encrypted_data_key_1, sentinel.encrypted_data_key_2]
        )

    def test_source_data_key_length_check_valid(self):
        mock_algorithm = MagicMock()
        mock_algorithm.kdf_input_len = 5
        mock_data_key = MagicMock()
        mock_data_key.data_key = "12345"
        aws_encryption_sdk.internal.utils.source_data_key_length_check(
            source_data_key=mock_data_key, algorithm=mock_algorithm
        )

    def test_source_data_key_length_check_invalid(self):
        mock_algorithm = MagicMock()
        mock_algorithm.kdf_input_len = 5
        mock_data_key = MagicMock()
        mock_data_key.data_key = "1234"
        with pytest.raises(InvalidDataKeyError) as excinfo:
            aws_encryption_sdk.internal.utils.source_data_key_length_check(
                source_data_key=mock_data_key, algorithm=mock_algorithm
            )
        excinfo.match("Invalid Source Data Key length 4 for algorithm required: 5")
