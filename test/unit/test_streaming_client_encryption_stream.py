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
"""Unit test suite for aws_encryption_sdk.streaming_client._EncryptionStream"""
import io
import unittest

import attr
from mock import call, MagicMock, patch, PropertyMock, sentinel
import six

import aws_encryption_sdk.exceptions
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.streaming_client import _ClientConfig, _EncryptionStream
from .test_values import VALUES


@attr.s
class MockClientConfig(_ClientConfig):
    mock_read_bytes = attr.ib(default=None)


class MockEncryptionStream(_EncryptionStream):
    output_buffer = b''
    _config_class = MockClientConfig

    def _prep_message(self):
        pass

    def _read_bytes(self, b):
        return self.config.mock_read_bytes


class TestEncryptionStream(unittest.TestCase):

    def setUp(self):
        self.mock_source_stream = MagicMock()
        self.mock_source_stream.__class__ = io.IOBase
        self.mock_source_stream.tell.side_effect = (10, 500)

        self.mock_key_provider = MagicMock()
        self.mock_key_provider.__class__ = MasterKeyProvider

        self.mock_line_length = MagicMock()
        self.mock_line_length.__class__ = int

        self.mock_source_length = MagicMock()
        self.mock_source_length.__class__ = int

    def test_read_bytes_enforcement(self):
        class TestStream(_EncryptionStream):
            _config_class = MockClientConfig

            def _prep_message(self):
                pass

        with six.assertRaisesRegex(self, TypeError, "Can't instantiate abstract class TestStream"):
            TestStream()

    def test_prep_message_enforcement(self):
        class TestStream(_EncryptionStream):
            _config_class = MockClientConfig

            def _read_bytes(self):
                pass

        with six.assertRaisesRegex(self, TypeError, "Can't instantiate abstract class TestStream"):
            TestStream()

    def test_config_class_enforcement(self):
        class TestStream(_EncryptionStream):
            def _read_bytes(self):
                pass

            def _prep_message(self):
                pass

        with six.assertRaisesRegex(self, TypeError, "Can't instantiate abstract class TestStream"):
            TestStream()

    def test_new_with_params(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes,
            line_length=self.mock_line_length,
            source_length=self.mock_source_length
        )
        assert mock_stream.config == MockClientConfig(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes,
            line_length=self.mock_line_length,
            source_length=self.mock_source_length
        )
        assert mock_stream.bytes_read == 0
        assert mock_stream.output_buffer == b''
        assert not mock_stream._message_prepped
        assert mock_stream.source_stream is self.mock_source_stream
        assert mock_stream._stream_length is self.mock_source_length
        assert mock_stream.line_length == io.DEFAULT_BUFFER_SIZE

    def test_new_with_config(self):
        mock_config = MagicMock()
        mock_config.__class__ = MockClientConfig
        mock_stream = MockEncryptionStream(config=mock_config)
        assert mock_stream.config is mock_config

    def test_enter(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        test = mock_stream.__enter__()
        assert test is mock_stream

    @patch('aws_encryption_sdk.streaming_client._EncryptionStream.close')
    def test_exit(self, mock_close):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        test = mock_stream.__exit__(None, None, None)
        mock_close.assert_called_once_with()
        assert not test

    @patch('aws_encryption_sdk.streaming_client._EncryptionStream.close')
    def test_exit_with_known_error(self, mock_close):
        mock_close.side_effect = aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        test = mock_stream.__exit__(None, None, None)
        mock_close.assert_called_once_with()
        assert not test

    @patch('aws_encryption_sdk.streaming_client._EncryptionStream.close')
    def test_exit_with_unknown_error(self, mock_close):
        class CustomUnknownError(Exception):
            pass

        mock_close.side_effect = CustomUnknownError
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        with self.assertRaises(CustomUnknownError):
            mock_stream.__exit__(None, None, None)

    def test_stream_length(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        assert mock_stream._stream_length is None
        test = mock_stream.stream_length
        self.mock_source_stream.tell.assert_has_calls(calls=(call(), call()))
        self.mock_source_stream.seek.assert_has_calls(
            calls=(
                call(0, 2),
                call(10, 0)
            ),
            any_order=False
        )
        assert mock_stream._stream_length == 500
        assert test == 500

    def test_stream_length_unsupported(self):
        self.mock_source_stream.tell.side_effect = Exception('Unexpected exception!')
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        with six.assertRaisesRegex(self, aws_encryption_sdk.exceptions.NotSupportedError, 'Unexpected exception!'):
            mock_stream.stream_length  # pylint: disable=pointless-statement

    def test_header_property(self):
        mock_prep_message = MagicMock()
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream._prep_message = mock_prep_message
        mock_stream._message_prepped = False
        mock_stream._header = sentinel.header
        test_header = mock_stream.header
        mock_prep_message.assert_called_once_with()
        assert test_header is sentinel.header

    def test_header_property_already_parsed(self):
        mock_prep_message = MagicMock()
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream._prep_message = mock_prep_message
        mock_stream._message_prepped = True
        mock_stream._header = sentinel.header
        test_header = mock_stream.header
        assert not mock_prep_message.called
        assert test_header is sentinel.header

    def test_read_closed(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream.close()
        with six.assertRaisesRegex(self, ValueError, 'I/O operation on closed file'):
            mock_stream.read()

    def test_read_b(self):
        mock_stream = MockEncryptionStream(
            source=io.BytesIO(VALUES['data_128']),
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream._read_bytes = MagicMock()
        mock_stream.output_buffer = b'1234567890'
        test = mock_stream.read(5)
        mock_stream._read_bytes.assert_called_once_with(5)
        assert test == b'12345'
        assert mock_stream.output_buffer == b'67890'

    def test_read_all(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream._stream_length = 5
        mock_stream.output_buffer = b'1234567890'
        mock_stream.source_stream = MagicMock()
        type(mock_stream.source_stream).closed = PropertyMock(side_effect=(False, False, True))
        test = mock_stream.read()
        assert test == b'1234567890'

    def test_read_all_empty_source(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream._stream_length = 0
        mock_stream.output_buffer = b''
        mock_stream.source_stream = MagicMock()
        mock_stream._read_bytes = MagicMock()
        type(mock_stream.source_stream).closed = PropertyMock(side_effect=(False, True))
        mock_stream.read()
        mock_stream._read_bytes.assert_called_once_with(1)

    def test_tell(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream.bytes_read = sentinel.bytes_read
        test = mock_stream.tell()
        assert test is sentinel.bytes_read

    def test_writable(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        assert not mock_stream.writable()

    def test_writelines(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        with six.assertRaisesRegex(self, NotImplementedError, 'writelines is not available for this object'):
            mock_stream.writelines(None)

    def test_write(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        with six.assertRaisesRegex(self, NotImplementedError, 'write is not available for this object'):
            mock_stream.write(None)

    def test_seek(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        with six.assertRaisesRegex(self, NotImplementedError, 'seek is not available for this object'):
            mock_stream.seek(None)

    def test_readline(self):
        test_line = 'TEST_LINE_AAAA'
        test_line_length = len(test_line)
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=test_line
        )
        mock_stream.line_length = test_line_length
        mock_stream.read = MagicMock()
        mock_stream.read.return_value = test_line
        mock_stream.close = MagicMock()
        test = mock_stream.readline()
        mock_stream.read.assert_called_once_with(test_line_length)
        assert not mock_stream.close.called
        assert test is test_line

    @patch('aws_encryption_sdk.streaming_client._EncryptionStream.__iter__')
    def test_readlines(self, mock_iter):
        lines = [
            sentinel.line_a,
            sentinel.line_b
        ]
        mock_iter.return_value = iter(lines)
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        test = mock_stream.readlines()
        assert test == lines

    def test_next(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        self.mock_source_stream.closed = False
        mock_stream.readline = MagicMock(return_value=sentinel.line)
        test = mock_stream.next()
        mock_stream.readline.assert_called_once_with()
        assert test is sentinel.line

    def test_next_stream_closed(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        mock_stream.close()
        with self.assertRaises(StopIteration):
            mock_stream.next()

    def test_next_source_stream_closed_and_buffer_empty(self):
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        self.mock_source_stream.closed = True
        mock_stream.output_buffer = b''
        with self.assertRaises(StopIteration):
            mock_stream.next()

    @patch('aws_encryption_sdk.streaming_client._EncryptionStream.closed', new_callable=PropertyMock)
    def test_iteration(self, mock_closed):
        mock_closed.side_effect = (False, False, False, False, True)
        self.mock_source_stream.closed = False
        mock_stream = MockEncryptionStream(
            source=self.mock_source_stream,
            key_provider=self.mock_key_provider,
            mock_read_bytes=sentinel.read_bytes
        )
        lines = [
            sentinel.line_1,
            sentinel.line_2,
            sentinel.line_3,
            sentinel.line_4
        ]
        mock_stream.readline = MagicMock(side_effect=lines)
        test_lines = []
        for line in mock_stream:
            test_lines.append(line)
        assert test_lines == lines
