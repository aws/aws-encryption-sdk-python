"""High level AWS Encryption SDK client for streaming objects."""
from __future__ import division
import abc
import codecs
import io
import logging
import math

import attr
import six

from aws_encryption_sdk.exceptions import SerializationError, CustomMaximumValueExceeded, NotSupportedError
import aws_encryption_sdk.internal.crypto
import aws_encryption_sdk.internal.defaults
import aws_encryption_sdk.internal.formatting.deserialize
import aws_encryption_sdk.internal.formatting.encryption_context
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.identifiers import Algorithm, ContentType
import aws_encryption_sdk.internal.utils
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.structures import MessageHeader

_LOGGER = logging.getLogger(__name__)


@attr.s
@six.add_metaclass(abc.ABCMeta)
class _ClientConfig(object):
    """Parent configuration object for StreamEncryptor and StreamDecryptor objects.

    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for encryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    """
    source = attr.ib(convert=aws_encryption_sdk.internal.utils.prep_stream_data)
    key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyProvider))
    source_length = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )
    line_length = attr.ib(
        default=aws_encryption_sdk.internal.defaults.LINE_LENGTH,
        validator=attr.validators.instance_of(int)
    )


class _EncryptionStream(io.IOBase):
    """Parent class for StreamEncryptor and StreamDecryptor classes.

    :param config: Client configuration object
    :type config: aws_encryption_sdk.streaming_client._ClientConfig
    """

    """
    abc.ABCMeta does not behave properly for defining abstractmethods in children of io.IOBase
        due to complexities in how __new__ is called (or not called) with C-module objects.
    Leaving this here as an explanation of what is going on in __new__

    @abc.abstractmethod
    def _read_bytes(self, b):
        Reads the requested number of bytes from the source stream.

        :param int b: Number of bytes to read
        :returns: Processed (encrypted or decrypted) bytes from source stream
        :rtype: str

    @abc.abstractmethod
    def _prep_message(self):
        Performs initial message setup.

    @abc.abstractproperty
    def _config_class(self):
        Configuration class for this class
    """

    def __new__(cls, **kwargs):
        """Patch for abstractmethod-like enforcement in io.IOBase grandchildren."""
        if (
            not (hasattr(cls, '_read_bytes') and callable(cls._read_bytes))
            or not (hasattr(cls, '_prep_message') and callable(cls._read_bytes))
            or not hasattr(cls, '_config_class')
        ):
            raise TypeError("Can't instantiate abstract class {}".format(cls.__name__))

        instance = super(_EncryptionStream, cls).__new__(cls)

        config = kwargs.pop('config', None)
        if not isinstance(config, instance._config_class):
            config = instance._config_class(**kwargs)
        instance.config = config

        instance.bytes_read = 0
        instance.output_buffer = b''
        instance._message_prepped = False
        instance.source_stream = instance.config.source
        instance._stream_length = instance.config.source_length
        instance.line_length = instance.config.line_length

        return instance

    @property
    def stream_length(self):
        """Returns the length of the source stream, determining it if not already known."""
        if self._stream_length is None:
            current_position = self.source_stream.tell()
            self.source_stream.seek(0, 2)
            self._stream_length = self.source_stream.tell()
            self.source_stream.seek(current_position, 0)
        return self._stream_length

    @property
    def header(self):
        """Returns the message header, reading it if it is not already read.

        :returns: Parsed message header
        :rtype: aws_encryption_sdk.structures.MessageHeader
        """
        if not self._message_prepped:
            self._prep_message()
        return self._header

    def __enter__(self):
        """Handles entry to with block."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Handles closing of stream upon exist of with block."""
        try:
            self.close()
        except aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError:
            # Only raise unknown exceptions in close
            pass
        return False

    def read(self, b=None):
        """Returns either the requested number of bytes or the entire stream.

        :param int b: Number of bytes to read
        :returns: Processed (encrypted or decrypted) bytes from source stream
        :rtype: str
        """
        _LOGGER.debug('Stream read called, requesting %s bytes', b)
        if not self._message_prepped:
            self._prep_message()
        if self.closed:
            raise ValueError('I/O operation on closed file')
        if b:
            self._read_bytes(b)
            output = self.output_buffer[:b]
            self.output_buffer = self.output_buffer[b:]
        else:
            output = b''
            while not self.source_stream.closed:
                b = self.stream_length if self.stream_length else 1  # Edge case to handle empty source streams.
                self._read_bytes(b)
                output += self.output_buffer
                self.output_buffer = b''
        self.bytes_read += len(output)
        _LOGGER.debug('Returning %s bytes of %s bytes requested', len(output), b)
        return output

    def tell(self):
        """Returns the current position in the stream."""
        return self.bytes_read

    def writable(self):
        """Overwrites the parent writable method"""
        return False

    def writelines(self, lines):
        """Overwrites the parent writelines method"""
        raise NotImplementedError('writelines is not available for this object')

    def write(self, b):
        """Overwrites the parent write method"""
        raise NotImplementedError('write is not available for this object')

    def seek(self, offset, whence=0):
        """Overwrites the parent seek method"""
        raise NotImplementedError('seek is not available for this object')

    def readline(self):
        """Read a chunk of the output"""
        _LOGGER.info('reading line')
        line = self.read(self.line_length)
        if len(line) < self.line_length:
            _LOGGER.info('all lines read')
        return line

    def readlines(self):
        """Reads all chunks of output, outputting a list as defined in the IOBase specification."""
        return [line for line in self]

    def __iter__(self):
        """Make this class and subclasses identify as iterators."""
        return self

    def next(self):
        """Provides hook for Python2 iterator functionality."""
        _LOGGER.debug('reading next')
        if self.closed:
            _LOGGER.debug('stream is closed')
            raise StopIteration()
        if self.source_stream.closed and not self.output_buffer:
            _LOGGER.debug('nothing more to read')
            raise StopIteration()
        return self.readline()

    #: Provides hook for Python3 iterator functionality.
    __next__ = next


@attr.s
class EncryptorConfig(_ClientConfig):
    """Configuration object for StreamEncryptor class.

    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for encryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    :param dict encryption_context: Dictionary defining encryption context
    :param algorithm: Algorithm to use for encryption (optional)
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int frame_length: Frame length in bytes (optional)
    """
    encryption_context = attr.ib(
        default=attr.Factory(dict),
        validator=attr.validators.instance_of(dict)
    )
    algorithm = attr.ib(
        default=aws_encryption_sdk.internal.defaults.ALGORITHM,
        validator=attr.validators.instance_of(Algorithm)
    )
    frame_length = attr.ib(
        default=aws_encryption_sdk.internal.defaults.FRAME_LENGTH,
        validator=attr.validators.instance_of(int)
    )
    data_key = None


class StreamEncryptor(_EncryptionStream):
    """Provides a streaming encryptor for encrypting a stream source.
    Behaves as a standard file-like object.

    .. note::
        Take care when encrypting framed messages with large frame length and large non-framed
        messages.  See :class:`aws_encryption_sdk.stream` for more details.

    .. note::
        If config is provided, all other parameters are ignored.

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.EncryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for encryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    :param dict encryption_context: Dictionary defining encryption context
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int frame_length: Frame length in bytes
    """
    _config_class = EncryptorConfig

    def __init__(self, **kwargs):
        self.sequence_number = 1

        self.content_type = aws_encryption_sdk.internal.utils.content_type(self.config.frame_length)
        aws_encryption_sdk.internal.utils.validate_frame_length(self.config.frame_length, self.config.algorithm)

        if (
            self.config.frame_length == 0
            and (
                self.config.source_length is not None
                and self.config.source_length > aws_encryption_sdk.internal.defaults.MAX_NON_FRAMED_SIZE
            )
        ):
            raise SerializationError('Source too large for non-framed message')

    def _prep_message(self):
        """Performs initial message setup."""
        encryption_context = self.config.encryption_context.copy()

        message_id = aws_encryption_sdk.internal.utils.message_id()

        if self.config.algorithm.signing_algorithm_info is None:
            self.signer = None
        else:
            self.signer = aws_encryption_sdk.internal.crypto.Signer(self.config.algorithm)
            encryption_context[aws_encryption_sdk.internal.defaults.ENCODED_SIGNER_KEY] = codecs.decode(
                self.signer.encoded_public_key()
            )

        self.encryption_data_key, encrypted_data_keys = aws_encryption_sdk.internal.utils.prepare_data_keys(
            key_provider=self.config.key_provider,
            algorithm=self.config.algorithm,
            encryption_context=encryption_context,
            plaintext_rostream=aws_encryption_sdk.internal.utils.ROStream(self.source_stream),
            plaintext_length=self.config.source_length,
            data_key=self.config.data_key
        )
        self._header = MessageHeader(
            version=aws_encryption_sdk.internal.defaults.VERSION,
            type=aws_encryption_sdk.internal.defaults.TYPE,
            algorithm=self.config.algorithm,
            message_id=message_id,
            encryption_context=encryption_context,
            encrypted_data_keys=encrypted_data_keys,
            content_type=self.content_type,
            content_aad_length=0,
            header_iv_length=self.config.algorithm.iv_len,
            frame_length=self.config.frame_length
        )
        self._write_header()
        if self.content_type == ContentType.NO_FRAMING:
            self._prep_non_framed()
        self._message_prepped = True

    def _write_header(self):
        """Builds the message header and writes it to the output stream."""
        self.output_buffer += aws_encryption_sdk.internal.formatting.serialize.serialize_header(
            header=self._header,
            signer=self.signer
        )
        self.output_buffer += aws_encryption_sdk.internal.formatting.serialize.serialize_header_auth(
            algorithm=self.config.algorithm,
            header=self.output_buffer,
            message_id=self._header.message_id,
            encryption_data_key=self.encryption_data_key,
            signer=self.signer
        )

    def _prep_non_framed(self):
        """Prepare the opening data for a non-framed message."""
        aad_content_string = aws_encryption_sdk.internal.utils.get_aad_content_string(
            content_type=self.content_type,
            is_final_frame=True
        )
        associated_data = aws_encryption_sdk.internal.formatting.encryption_context.assemble_content_aad(
            message_id=self._header.message_id,
            aad_content_string=aad_content_string,
            seq_num=1,
            length=self.stream_length
        )
        self.encryptor = aws_encryption_sdk.internal.crypto.Encryptor(
            algorithm=self.config.algorithm,
            key=self.encryption_data_key.data_key,
            associated_data=associated_data,
            message_id=self._header.message_id
        )
        self.output_buffer += aws_encryption_sdk.internal.formatting.serialize.serialize_non_framed_open(
            algorithm=self.config.algorithm,
            iv=self.encryptor.iv,
            plaintext_length=self.stream_length,
            signer=self.signer
        )

    def _read_bytes_to_non_framed_body(self, b):
        """Reads the requested number of bytes from source to a streaming non-framed message body.

        :param int b: Number of bytes to read
        :returns: Encrypted bytes from source stream
        :rtype: str
        """
        _LOGGER.debug('Reading %s bytes', b)
        plaintext = self.source_stream.read(b)
        if self.tell() + len(plaintext) > aws_encryption_sdk.internal.defaults.MAX_NON_FRAMED_SIZE:
            raise SerializationError('Source too large for non-framed message')
        ciphertext = self.encryptor.update(plaintext)
        if self.signer:
            self.signer.update(ciphertext)
        if len(plaintext) < b:
            _LOGGER.debug('Closing encryptor after receiving only %s bytes of %s bytes requested', plaintext, b)
            self.source_stream.close()
            closing = self.encryptor.finalize()
            if self.signer:
                self.signer.update(closing)
            closing += aws_encryption_sdk.internal.formatting.serialize.serialize_non_framed_close(
                tag=self.encryptor.tag,
                signer=self.signer
            )
            if self.signer:
                closing += aws_encryption_sdk.internal.formatting.serialize.serialize_footer(self.signer)
            return ciphertext + closing
        return ciphertext

    def _read_bytes_to_framed_body(self, b):
        """Reads the requested number of bytes from source to a streaming framed message body.

        :param int b: Number of bytes to read
        :returns: Bytes read from source stream, encrypted, and serialized
        :rtype: bytes
        """
        _LOGGER.debug('collecting %s bytes', b)
        _b = b
        b = int(math.ceil(b / float(self.config.frame_length)) * self.config.frame_length)
        _LOGGER.debug('%s bytes requested; reading %s bytes after normalizing to frame length', _b, b)
        plaintext = self.source_stream.read(b)
        _LOGGER.debug('%s bytes read from source', len(plaintext))
        finalize = False
        if len(plaintext) < b:
            _LOGGER.debug('Final plaintext read from source')
            finalize = True
        output = b''
        final_frame_written = False

        while (
            (not finalize and plaintext)  # If not finalizing on this pass, exit when plaintext is exhausted
            or (finalize and not final_frame_written)  # If finalizing on this pass, wait until final frame is written
        ):
            is_final_frame = finalize and len(plaintext) < self.config.frame_length
            _LOGGER.debug(
                'Writing %s bytes into% frame %s',
                min(len(plaintext), self.config.frame_length),
                self.sequence_number,
                ' final' if is_final_frame else ''
            )
            ciphertext, plaintext = aws_encryption_sdk.internal.formatting.serialize.serialize_frame(
                algorithm=self.config.algorithm,
                plaintext=plaintext,
                message_id=self._header.message_id,
                encryption_data_key=self.encryption_data_key,
                frame_length=self.config.frame_length,
                sequence_number=self.sequence_number,
                is_final_frame=is_final_frame,
                signer=self.signer
            )
            final_frame_written = is_final_frame
            output += ciphertext
            self.sequence_number += 1

        if finalize:
            _LOGGER.debug('Writing footer')
            if self.signer:
                output += aws_encryption_sdk.internal.formatting.serialize.serialize_footer(self.signer)
            self.source_stream.close()
        return output

    def _read_bytes(self, b):
        """Reads the requested number of bytes from a streaming message body.

        :param int b: Number of bytes to read
        :raises NotSupportedError: if content type is not supported
        """
        _LOGGER.debug('%s bytes requested from stream with content type: %s', b, self.content_type)
        if b <= len(self.output_buffer) or self.source_stream.closed:
            _LOGGER.debug('No need to read from source stream or source stream closed')
            return

        if self.content_type == ContentType.FRAMED_DATA:
            _LOGGER.debug('Reading to framed body')
            self.output_buffer += self._read_bytes_to_framed_body(b)
        elif self.content_type == ContentType.NO_FRAMING:
            _LOGGER.debug('Reading to non-framed body')
            self.output_buffer += self._read_bytes_to_non_framed_body(b)
        else:
            raise NotSupportedError('Unsupported content type')

    def close(self):
        """Closes out the stream."""
        _LOGGER.debug('Closing stream')
        super(StreamEncryptor, self).close()


@attr.s
class DecryptorConfig(_ClientConfig):
    """Configuration object for StreamDecryptor class.

    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for encryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and read() is called, will attempt to seek()
            to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    :param int max_body_length: Maximum frame size (or content length for non-framed messages)
    in bytes to read from ciphertext message.
    """
    max_body_length = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )


class StreamDecryptor(_EncryptionStream):
    """Provides a streaming encryptor for encrypting a stream source.
    Behaves as a standard file-like object.

    .. note::
        Take care when decrypting framed messages with large frame length and large non-framed
        messages.  See :class:`aws_encryption_sdk.stream` for more details.

    .. note::
        If config is provided, all other parameters are ignored.

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.DecryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for decryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and read() is called, will attempt to seek()
            to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    :param int max_body_length: Maximum frame size (or content length for non-framed messages)
    in bytes to read from ciphertext message.
    """
    _config_class = DecryptorConfig

    def __init__(self, **kwargs):
        self.last_sequence_number = 0

    def _prep_message(self):
        """Performs initial message setup."""
        self._header, self.header_auth = self._read_header()
        if self._header.content_type == ContentType.NO_FRAMING:
            self._prep_non_framed()
        self._message_prepped = True

    def _read_header(self):
        """Reads the message header from the input stream.

        :returns: tuple containing deserialized header and header_auth objects
        :rtype: tuple of aws_encryption_sdk.structure.MessageHeader
            and aws_encryption_sdk.internal.structures.MessageHeaderAuthentication
        :raises CustomMaximumValueExceeded: if frame length is greater than the custom max value
        """
        header_start = self.source_stream.tell()
        header = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header(self.source_stream)

        if (
            self.config.max_body_length is not None
            and header.content_type == ContentType.FRAMED_DATA
            and header.frame_length > self.config.max_body_length
        ):
            raise CustomMaximumValueExceeded(
                'Frame Size in header found larger than custom value: {found} > {custom}'.format(
                    found=header.frame_length,
                    custom=self.config.max_body_length
                )
            )

        header_end = self.source_stream.tell()
        self.verifier = aws_encryption_sdk.internal.formatting.deserialize.verifier_from_header(header)
        if self.verifier:
            self.source_stream.seek(header_start)
            self.verifier.update(self.source_stream.read(header_end - header_start))
        header_auth = aws_encryption_sdk.internal.formatting.deserialize.deserialize_header_auth(
            stream=self.source_stream,
            algorithm=header.algorithm,
            verifier=self.verifier
        )
        self.data_key = self.config.key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=header.encrypted_data_keys,
            algorithm=header.algorithm,
            encryption_context=header.encryption_context
        )
        aws_encryption_sdk.internal.formatting.deserialize.validate_header(
            header=header,
            header_auth=header_auth,
            stream=self.source_stream,
            header_start=header_start,
            header_end=header_end,
            data_key=self.data_key
        )
        return header, header_auth

    def _prep_non_framed(self):
        """Prepare the opening data for a non-framed message."""
        iv, tag, self.body_length = aws_encryption_sdk.internal.formatting.deserialize.deserialize_non_framed_values(
            stream=self.source_stream,
            header=self._header,
            verifier=self.verifier
        )

        if self.config.max_body_length is not None and self.body_length > self.config.max_body_length:
            raise CustomMaximumValueExceeded(
                'Non-framed message content length found larger than custom value: {found} > {custom}'.format(
                    found=self.body_length,
                    custom=self.config.max_body_length
                )
            )

        aad_content_string = aws_encryption_sdk.internal.utils.get_aad_content_string(
            content_type=self._header.content_type,
            is_final_frame=True
        )
        associated_data = aws_encryption_sdk.internal.formatting.encryption_context.assemble_content_aad(
            message_id=self._header.message_id,
            aad_content_string=aad_content_string,
            seq_num=1,
            length=self.body_length
        )
        self.decryptor = aws_encryption_sdk.internal.crypto.Decryptor(
            algorithm=self._header.algorithm,
            key=self.data_key.data_key,
            associated_data=associated_data,
            message_id=self._header.message_id,
            iv=iv,
            tag=tag
        )
        self.body_start = self.source_stream.tell()
        self.body_end = self.body_start + self.body_length

    def _read_bytes_from_non_framed_body(self, b):
        """Reads the requested number of bytes from a streaming non-framed message body.

        :param int b: Number of bytes to read
        :returns: Decrypted bytes from source stream
        :rtype: str
        """
        _LOGGER.debug('starting non-framed body read')
        # Always read the entire message for non-framed message bodies.
        bytes_to_read = self.body_end - self.source_stream.tell()
        _LOGGER.debug('%s bytes requested; reading %s bytes', b, bytes_to_read)
        ciphertext = self.source_stream.read(bytes_to_read)
        if len(self.output_buffer) + len(ciphertext) < self.body_length:
            raise SerializationError('Total message body contents less than specified in body description')
        if self.verifier:
            self.verifier.update(ciphertext)
        plaintext = self.decryptor.update(ciphertext)
        plaintext += self.decryptor.finalize()
        aws_encryption_sdk.internal.formatting.deserialize.update_verifier_with_tag(
            stream=self.source_stream,
            header=self._header,
            verifier=self.verifier
        )
        self.footer = aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(
            stream=self.source_stream,
            verifier=self.verifier
        )
        self.source_stream.close()
        return plaintext

    def _read_bytes_from_framed_body(self, b):
        """Reads the requested number of bytes from a streaming framed message body.

        :param int b: Number of bytes to read
        :returns: Bytes read from source stream and decrypted
        :rtype: str
        """
        plaintext = b''
        final_frame = False
        _LOGGER.debug('collecting %s bytes', b)
        while len(plaintext) < b and not final_frame:
            _LOGGER.debug('Reading frame')
            frame_data, final_frame = aws_encryption_sdk.internal.formatting.deserialize.deserialize_frame(
                stream=self.source_stream,
                header=self._header,
                verifier=self.verifier
            )
            _LOGGER.debug('Read complete for frame %s'.format(frame_data.sequence_number))
            if frame_data.sequence_number != self.last_sequence_number + 1:
                raise SerializationError('Malformed message: frames out of order')
            self.last_sequence_number += 1
            aad_content_string = aws_encryption_sdk.internal.utils.get_aad_content_string(
                content_type=self._header.content_type,
                is_final_frame=frame_data.final_frame
            )
            associated_data = aws_encryption_sdk.internal.formatting.encryption_context.assemble_content_aad(
                message_id=self._header.message_id,
                aad_content_string=aad_content_string,
                seq_num=frame_data.sequence_number,
                length=len(frame_data.ciphertext)
            )
            plaintext += aws_encryption_sdk.internal.crypto.decrypt(
                algorithm=self._header.algorithm,
                key=self.data_key.data_key,
                encrypted_data=frame_data,
                associated_data=associated_data,
                message_id=self._header.message_id
            )
            _LOGGER.debug('bytes collected: %s', len(plaintext))
        if final_frame:
            _LOGGER.debug('Reading footer')
            self.footer = aws_encryption_sdk.internal.formatting.deserialize.deserialize_footer(
                stream=self.source_stream,
                verifier=self.verifier
            )
            self.source_stream.close()
        return plaintext

    def _read_bytes(self, b):
        """Reads the requested number of bytes from a streaming message body.

        :param int b: Number of bytes to read
        :raises NotSupportedError: if content type is not supported
        """
        if self.source_stream.closed:
            _LOGGER.debug('Source stream closed')
            return

        if b <= len(self.output_buffer):
            _LOGGER.debug(
                '%s bytes requested less than or equal to current output buffer size %s',
                b,
                len(self.output_buffer)
            )
            return

        if self._header.content_type == ContentType.FRAMED_DATA:
            self.output_buffer += self._read_bytes_from_framed_body(b)
        elif self._header.content_type == ContentType.NO_FRAMING:
            self.output_buffer += self._read_bytes_from_non_framed_body(b)
        else:
            raise NotSupportedError('Unsupported content type')

    def close(self):
        """Closes out the stream."""
        _LOGGER.debug('Closing stream')
        if not hasattr(self, 'footer'):
            raise SerializationError('Footer not read')
        super(StreamDecryptor, self).close()
