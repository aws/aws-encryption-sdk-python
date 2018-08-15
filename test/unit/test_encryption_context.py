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
"""Unit test suite for aws_encryption_sdk.internal.formatting.encryption_context"""
import unittest

import pytest
import six

import aws_encryption_sdk.internal.defaults
import aws_encryption_sdk.internal.formatting.encryption_context
from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.identifiers import ContentAADString

from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestEncryptionContext(unittest.TestCase):
    def test_assemble_content_aad(self):
        """Validate that the assemble_content_aad function
            behaves as expected.
        """
        test = aws_encryption_sdk.internal.formatting.encryption_context.assemble_content_aad(
            message_id=VALUES["message_id"],
            aad_content_string=ContentAADString.NON_FRAMED_STRING_ID,
            seq_num=1,
            length=VALUES["content_len"],
        )
        assert test == VALUES["non_framed_aac"]

    def test_assemble_content_aad_unknown_type(self):
        with six.assertRaisesRegex(self, SerializationError, "Unknown aad_content_string"):
            aws_encryption_sdk.internal.formatting.encryption_context.assemble_content_aad(
                message_id=VALUES["message_id"], aad_content_string=None, seq_num=1, length=VALUES["content_len"]
            )

    def test_serialize_encryption_context_no_encryption_context(self):
        """Validate that the serialize_encryption_context
            function behaves as expected when presented
            with an empty encryption context.
        """
        test = aws_encryption_sdk.internal.formatting.encryption_context.serialize_encryption_context({})
        assert test == bytes()

    def test_serialize_encryption_context_too_many_elements(self):
        """Validate that the serialize_encryption_context
            function behaves as expected when presented
            with an encryption context with too many
            elements.
        """
        with six.assertRaisesRegex(self, SerializationError, "The encryption context contains too many elements."):
            aws_encryption_sdk.internal.formatting.encryption_context.serialize_encryption_context(
                VALUES["encryption_context_too_many_elements"]
            )

    def test_serialize_encryption_context_too_large(self):
        """Validate that the serialize_encryption_context
            function behaves as expected when presented
            with an encryption context which is too large.
        """
        with six.assertRaisesRegex(self, SerializationError, "The serialized context is too large"):
            aws_encryption_sdk.internal.formatting.encryption_context.serialize_encryption_context(
                VALUES["encryption_context_too_large"]
            )

    def test_serialize_encryption_context_unencodable(self):
        """Validate that the serialize_encryption_context
            function behaves as expected when presented
            with an encryption context which contains
            unencodable elements.
        """
        for encryption_context in [{"a": b"\xc4"}, {b"\xc4": "a"}, {b"\xc4": b"\xc4"}]:
            with six.assertRaisesRegex(self, SerializationError, "Cannot encode dictionary key or value using *"):
                aws_encryption_sdk.internal.formatting.encryption_context.serialize_encryption_context(
                    encryption_context
                )

    def test_serialize_encryption_context_valid(self):
        """Validate that the serialize_encryption_context
            function behaves as expected for a valid
            encryption context.
        """
        test = aws_encryption_sdk.internal.formatting.encryption_context.serialize_encryption_context(
            VALUES["updated_encryption_context"]
        )
        assert test == VALUES["serialized_encryption_context"]

    def test_read_short_too_short(self):
        """Validate that the read_short function behaves
            as expected when it encounters a struct error.
        """
        with six.assertRaisesRegex(self, SerializationError, "Bad format of serialized context."):
            aws_encryption_sdk.internal.formatting.encryption_context.read_short(b"d", 0)

    def test_read_short_valid(self):
        """Validate that the read_short function behaves
            as expected with a valid call.
        """
        test_value, test_offset = aws_encryption_sdk.internal.formatting.encryption_context.read_short(b"\x00\x05df", 0)
        assert test_value == 5
        assert test_offset == 2

    def test_read_string_encoding_error(self):
        """Validate that the read_string function behaves
            as expected when it encounters an encoding
            error.
        """
        with six.assertRaisesRegex(self, SerializationError, "Bad format of serialized context."):
            aws_encryption_sdk.internal.formatting.encryption_context.read_string(b"\xc4", 0, 1)

    def test_read_string_valid(self):
        """Validate that the read_string function behaves
            as expected with a valid call.
        """
        test_value, test_offset = aws_encryption_sdk.internal.formatting.encryption_context.read_string(b"asdf", 0, 2)
        assert test_value == "as"
        assert test_offset == 2

    def test_deserialize_encryption_context_too_large(self):
        """Validate that the deserialize_encryption_context
            function behaves as expected when it encounters
            a serialized encryption context which is too
            large.
        """
        data = ""
        for i in range(aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE + 1):
            data += str(i)
        with six.assertRaisesRegex(self, SerializationError, "Serialized context is too long."):
            aws_encryption_sdk.internal.formatting.encryption_context.deserialize_encryption_context(
                serialized_encryption_context=data
            )

    def test_deserialize_encryption_context_duplicate_key(self):
        """Validate that the deserialize_encryption_context
            function behaves as expected when it encounters
            a serialized encryption context which contains
            duplicate keys.
        """
        with six.assertRaisesRegex(self, SerializationError, "Duplicate key in serialized context."):
            aws_encryption_sdk.internal.formatting.encryption_context.deserialize_encryption_context(
                serialized_encryption_context=VALUES["serialized_encryption_context_duplicate_key"]
            )

    def test_deserialize_encryption_context_extra_data(self):
        """Validate that the deserialize_encryption_context
            function behaves as expected when it encounters
            a serialized encryption context which contains
            extra data after processing the encoded number
            of pairs (formatting error).
        """
        data = VALUES["serialized_encryption_context"] + b"jhofguijhsuskldfh"
        with six.assertRaisesRegex(self, SerializationError, "Formatting error: Extra data in serialized context."):
            aws_encryption_sdk.internal.formatting.encryption_context.deserialize_encryption_context(
                serialized_encryption_context=data
            )

    def test_deserialize_encryption_context_valid(self):
        """Validate that the deserialize_encryption_context
            function behaves as expected for a valid
            encryption context.
        """
        test = aws_encryption_sdk.internal.formatting.encryption_context.deserialize_encryption_context(
            serialized_encryption_context=VALUES["serialized_encryption_context"]
        )
        assert test == VALUES["updated_encryption_context"]

    def test_deserialize_encryption_context_empty(self):
        """Validate that the deserialize_encryption_context
            function behaves as expected for an empty
            encryption context.
        """
        test = aws_encryption_sdk.internal.formatting.encryption_context.deserialize_encryption_context(
            serialized_encryption_context=b""
        )
        assert test == {}
