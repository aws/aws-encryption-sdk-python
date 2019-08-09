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
import base64
import io
import struct

import pytest
from cryptography.exceptions import InvalidTag
from mock import MagicMock, patch, sentinel

import aws_encryption_sdk.internal.formatting.deserialize
from aws_encryption_sdk.exceptions import NotSupportedError, SerializationError, UnknownIdentityError
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.internal.structures import EncryptedData

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_deserialize_non_framed_values():
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11"
    length = 42
    packed = struct.pack(">12sQ", iv, length)
    mock_header = MagicMock(algorithm=MagicMock(iv_len=12))

    parsed_iv, parsed_length = aws_encryption_sdk.internal.formatting.deserialize.deserialize_non_framed_values(
        stream=io.BytesIO(packed), header=mock_header
    )

    assert parsed_iv == iv
    assert parsed_length == length


def test_deserialize_tag():
    tag = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15"
    packed = struct.pack(">16s", tag)
    mock_header = MagicMock(algorithm=MagicMock(auth_len=16))

    parsed_tag = aws_encryption_sdk.internal.formatting.deserialize.deserialize_tag(
        stream=io.BytesIO(packed), header=mock_header
    )

    assert parsed_tag == tag


class TestDeserialize(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
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
            "aws_encryption_sdk.internal.formatting.encryption_context.deserialize_encryption_context"
        )
        self.mock_deserialize_ec = self.mock_deserialize_ec_patcher.start()
        self.mock_deserialize_ec.return_value = VALUES["updated_encryption_context"]
        # Set up mock verifier
        self.mock_verifier = MagicMock()
        self.mock_verifier.update.return_value = None
        yield
        # Run tearDown
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
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.validate_header(
                header=VALUES["deserialized_header_block"],
                header_auth=VALUES["deserialized_header_auth_block"],
                raw_header=VALUES["header"],
                data_key=VALUES["data_key_obj"],
            )
        excinfo.match("Header authorization failed")

    def test_deserialize_header_unknown_object_type(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown object type.
        """
        with pytest.raises(NotSupportedError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_invalid_object_type"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Unsupported type *")

    def test_deserialize_header_unknown_version(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown message version.
        """
        with pytest.raises(NotSupportedError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_invalid_version"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Unsupported version *")

    @patch("aws_encryption_sdk.internal.formatting.deserialize.AlgorithmSuite.get_by_id")
    def test_deserialize_header_unsupported_data_encryption_algorithm(self, mock_algorithm_get):
        """Validate that the deserialize_header function behaves
            as expected for an unsupported/disallowed algorithm.
        """
        mock_unsupported_algorithm = MagicMock()
        mock_unsupported_algorithm.allowed = False
        mock_algorithm_get.return_value = mock_unsupported_algorithm
        with pytest.raises(NotSupportedError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_disallowed_algorithm"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Unsupported algorithm *")

    @patch("aws_encryption_sdk.internal.formatting.deserialize.AlgorithmSuite.get_by_id")
    def test_deserialize_header_unknown_data_encryption_algorithm(self, mock_algorithm_get):
        """Validate that the deserialize_header function behaves
            as expected for an unknown algorithm.
        """
        mock_algorithm_get.side_effect = KeyError()
        with pytest.raises(UnknownIdentityError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_invalid_algorithm"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Unknown algorithm *")

    def test_deserialize_header_unknown_content_type(self):
        """Validate that the deserialize_header function behaves
            as expected for an unknown content type.
        """
        with pytest.raises(UnknownIdentityError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_unknown_content_type"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Unknown content type *")

    """
    Decoded looks like this (with important incorrect AAD fields on their own lines):
    b'\x01\x80\x00\x14\x9c\r\xf0\x88\x10\xf7\xed,\xc7,\xbb\xfb\xdd\x1c\x08(
        \x00\x02
        \x00\x00
        \x00\x01\x00\x13WEB-CRYPTO-RSA-OAEP\x00(8CED2FD20FC88A9C06EFDB073707EB1EF1655780\x01
        \x00V\xc8\x8b\xe8&J\xbb\xde\x8d\xf3\x82\x8d\xb14\xf2\xb4\xd8\x1f)\xb6\xb8\xb5\xac\x8a,\xd0\x1et\xf2
        \xdf??U\xe4~\xec\xc2\xaf6\xfe\xd9|\xf7\xf9-~\xe2\xf5\xa9\x98\xc3\x10\x8c!+\xd8\xf8\x10\x9c\x9d\xd2
        \xda\x90\x7f\xd1\x945\x1d\x83>\x7fCB\x80\xc6\xb19-~\xc3\x1f\x13\xbf\xc0\xcb\xe2$(\xbe\xa9u\x8co\xeen
        \xd2hpz\x94b\x84\xef\xdd\x93\xed\xe4\x1a\xac\x9a.\x19\xc6\xb8\x0e\xb1\xa9\x89\x93\x85IBe\x1eA\xc1\xfc
        \x84u\xd4\x9a\x9e\n;\xbaa\x16\xc3V\x10\xf2\xfa$\x8e\xa53\x08\xa4r\x93ui_\x04\x13]\x02\xcb\xac\x1c
        \xfbff{\x02|\xe7\xd1*\x1a-\x89<\x0fJ\xcfZ\x12\x87\xbdE\xd0\x0c\x96\x03a\xd4;\xbe\x97\x9d\xc6\x9b\x04
        \xe6\xf9b,\x8f|\x08\x07\x08ZYd\xb2\xdfz\xe02\x01\xc0\xa8\x00_\xa2\x1c\xf0\xd8\xfe\xf1>\xd5\xba\xb7J
        \xd9!nL~\x0b"\xf9\x1ena\x06\x0b\x19\xe0u\x1a_\xa2\x91\x14\xfd\x17t-\x85\xd9\x8aN\x02\x00\x00\x00\x00
        \x0c\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00+\xdb\xcdF\xfc\xa6\x0eJ1;\xa7r\xeb
        \xbaC\xb9\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00
        \x050*\x9a)P\xad\xa8\x13\x156\x1d?=\xb7\xc3SLG\xe7<S'
    """

    def test_deserialize_header_malformed_aad(self):
        mencoded = b"AYAAFJwN8IgQ9+0sxyy7+90cCCgAAgAAAAEAE1dFQi1DUllQVE8tUlNBLU9BRVAAKDhDRUQyRkQyMEZDODhBOUMwNkVGREIwNzM3MDdFQjFFRjE2NTU3ODABAFbIi+gmSrvejfOCjbE08rTYHym2uLWsiizQHnTy3z8/VeR+7MKvNv7ZfPf5LX7i9amYwxCMISvY+BCcndLakH/RlDUdgz5/Q0KAxrE5LX7DHxO/wMviJCi+qXWMb+5u0mhwepRihO/dk+3kGqyaLhnGuA6xqYmThUlCZR5BwfyEddSango7umEWw1YQ8vokjqUzCKRyk3VpXwQTXQLLrBz7ZmZ7Anzn0SoaLYk8D0rPWhKHvUXQDJYDYdQ7vpedxpsE5vliLI98CAcIWllkst964DIBwKgAX6Ic8Nj+8T7VurdK2SFuTH4LIvkebmEGCxngdRpfopEU/Rd0LYXZik4CAAAAAAwAAAAGAAAAAAAAAAAAAAAAK9vNRvymDkoxO6dy67pDuf////8AAAABAAAAAAAAAAAAAAABAAAABTAqmilQragTFTYdPz23w1NMR+c8Uw=="
        mdecoded = base64.b64decode(mencoded)
        malformed_header = io.BytesIO(mdecoded)

        with pytest.raises(SerializationError) as excinfo:
            test = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(malformed_header)
        excinfo.match(r"Malformed AAD: zero length AAD with non-zero length AAD length field")

    def test_deserialize_header_invalid_reserved_space(self):
        """Validate that the deserialize_header function behaves
            as expected for an invalid value in the reserved
            space (formerly content AAD).
        """
        with pytest.raises(SerializationError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_bad_reserved_space"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Content AAD length field is currently unused, its value must be always 0")

    def test_deserialize_header_bad_iv_len(self):
        """Validate that the deserialize_header function behaves
            as expected for bad IV length (incompatible with
            specified algorithm).
        """
        with pytest.raises(SerializationError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_bad_iv_len"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Specified IV length *")

    def test_deserialize_header_framed_bad_frame_length(self):
        """Validate that the deserialize_header function behaves
            as expected for bad frame length values (greater than
            the default maximum).
        """
        with pytest.raises(SerializationError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_header_bad_frame_len"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Specified frame length larger than allowed maximum: *")

    def test_deserialize_header_non_framed_bad_frame_length(self):
        """Validate that the deserialize_header function behaves
            as expected for bad frame length values for non-framed
            messages (non-zero).
        """
        with pytest.raises(SerializationError) as excinfo:
            stream = io.BytesIO(VALUES["serialized_non_framed_header_bad_frame_len"])
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(stream)
        excinfo.match("Non-zero frame length found for non-framed message")

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
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
                stream=stream, header=VALUES["deserialized_header_frame"]
            )
        excinfo.match("Invalid final frame length: *")

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
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(stream, self.mock_verifier)
        excinfo.match("No signature found in message")

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
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=b"asifuhasjaskldjfhlsakdfj",
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"]["wrapped_encrypted_data_key_asymmetric"],
            )
        excinfo.match("Master Key mismatch for wrapped data key")

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_info(self):
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_info"
                ],
            )
        excinfo.match("Malformed key info: key info missing data")

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_iv_len_mismatch(self):
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_bad_iv_len"
                ],
            )
        excinfo.match("Wrapping AlgorithmSuite mismatch for wrapped data key")

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_iv(self):
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_iv"
                ],
            )
        excinfo.match("Malformed key info: incomplete iv")

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_tag(self):
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_tag"
                ],
            )
        excinfo.match("Malformed key info: incomplete ciphertext or tag")

    def test_deserialize_wrapped_key_symmetric_wrapping_algorithm_incomplete_tag2(self):
        with pytest.raises(SerializationError) as excinfo:
            aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key_id=VALUES["wrapped_keys"]["raw"]["key_info"],
                wrapped_encrypted_key=VALUES["wrapped_keys"]["structures"][
                    "wrapped_encrypted_data_key_symmetric_incomplete_tag2"
                ],
            )
        excinfo.match("Malformed key info: incomplete ciphertext or tag")
