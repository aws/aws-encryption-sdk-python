"""Helper utility functions for AWS Encryption SDK."""
import io
import logging
import os

import six

from aws_encryption_sdk.exceptions import (
    ActionNotAllowedError, NotSupportedError, SerializationError,
    UnknownIdentityError, InvalidDataKeyError, MasterKeyProviderError
)
import aws_encryption_sdk.internal.defaults
from aws_encryption_sdk.identifiers import ContentAADString, ContentType
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.structures import RawDataKey, DataKey

_LOGGER = logging.getLogger(__name__)


def content_type(frame_length):
    """Returns the appropriate content type based on the frame length.

    :param int frame_length: Message frame length
    :returns: Appropriate content type based on frame length
    :rtype: aws_encryption_sdk.identifiers.ContentType
    """
    if frame_length == 0:
        return ContentType.NO_FRAMING
    else:
        return ContentType.FRAMED_DATA


def validate_frame_length(frame_length, algorithm):
    """Validates that frame length is within the defined limits and is compatible with the selected algorithm.

    :param int frame_length: Frame size in bytes
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :raises SerializationError: if frame size is negative or not a multiple of the algorithm block size
    :raises SerializationError: if frame size is larger than the maximum allowed frame size
    """
    if frame_length < 0 or frame_length % algorithm.encryption_algorithm.block_size != 0:
        raise SerializationError(
            'Frame size must be a non-negative multiple of the block size of the crypto algorithm: {block_size}'.format(
                block_size=algorithm.encryption_algorithm.block_size
            )
        )
    if frame_length > aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE:
        raise SerializationError('Frame size too large: {frame} > {max}'.format(
            frame=frame_length,
            max=aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE
        ))


def message_id():
    """Generates a new message ID.

    :returns: Message ID
    :rtype: str
    """
    return os.urandom(aws_encryption_sdk.internal.defaults.MESSAGE_ID_LENGTH)


def get_aad_content_string(content_type, is_final_frame):
    """Prepares the appropriate Body AAD Value for a message body.

    :param content_type: Defines the type of content for which to prepare AAD String
    :type content_type: aws_encryption_sdk.identifiers.ContentType
    :param bool is_final_frame: Boolean stating whether this is the final frame in a body
    :returns: Appropriate AAD Content String
    :rtype: str
    :raises UnknownIdentityError: if unknown content type
    """
    if content_type == ContentType.NO_FRAMING:
        aad_content_string = ContentAADString.NON_FRAMED_STRING_ID
    elif content_type == ContentType.FRAMED_DATA:
        if is_final_frame:
            aad_content_string = ContentAADString.FINAL_FRAME_STRING_ID
        else:
            aad_content_string = ContentAADString.FRAME_STRING_ID
    else:
        raise UnknownIdentityError('Unhandled content type')
    return aad_content_string


class ROStream(object):
    """Provides a read-only interface on top of a stream object.

    Used to provide MasterKeyProviders with read-only access to plaintext.

    :param source_stream: File-like object
    """

    def __init__(self, source_stream):
        self._source_stream = source_stream
        self._duplicate_api()

    def _duplicate_api(self):
        """Maps the source stream API onto this object."""
        source_attributes = set([
            method for method in dir(self._source_stream)
            if not method.startswith('_')
        ])
        self_attributes = set(dir(self))
        for attribute in source_attributes.difference(self_attributes):
            setattr(self, attribute, getattr(self._source_stream, attribute))

    def write(self, b):
        """Blocks calls to write.

        :raises ActionNotAllowedError: when called
        """
        raise ActionNotAllowedError('Write not allowed on ROStream objects')


def prepare_data_keys(
    key_provider,
    algorithm,
    encryption_context,
    plaintext_rostream,
    plaintext_length=None,
    data_key=None
):
    """Prepares a DataKey to be used for encrypting message and list
    of EncryptedDataKey objects to be serialized into header.

    :param key_provider: Master Key Provider to use
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param dict encryption_context: Encryption context to use when generating data key
    :param plaintext_stream: Source plaintext read-only stream
    :type plaintext_rostream: aws_encryption_sdk.internal.utils.ROStream
    :param int plaintext_length: Length of source plaintext (optional)
    :param data_key: Object containing data key to use (if not supplied, a new key will be generated)
    :type data_key: :class:`aws_encryption_sdk.structure.DataKey`
        or :class:`aws_encryption_sdk.structure.RawDataKey`
    :rtype: tuple containing :class:`aws_encryption_sdk.structure.RawDataKey`
        and set of :class:`aws_encryption_sdk.structure.EncryptedDataKey`
    :raises SerializationError: if primary master key is not a member of supplied MasterKeyProvider
    :raises NotSupportedError: if data_key is not a supported data type
    :raises MasterKeyProviderError: if no Master Keys are returned from key_provider
    """
    primary_master_key, master_keys = key_provider.master_keys_for_encryption(
        encryption_context=encryption_context,
        plaintext_rostream=plaintext_rostream,
        plaintext_length=plaintext_length
    )
    if not master_keys:
        raise MasterKeyProviderError('No Master Keys available from Master Key Provider')
    if primary_master_key not in master_keys:
        raise MasterKeyProviderError('Primary Master Key not in provided Master Keys')
    encrypted_data_keys = set()
    encrypted_encryption_data_key = None
    if not data_key:
        encryption_data_key = primary_master_key.generate_data_key(algorithm, encryption_context)
        _LOGGER.debug('encryption data key generated from primary master key')
    elif isinstance(data_key, RawDataKey):
        encryption_data_key = data_key
        _LOGGER.debug('raw encryption data key provided')
    elif isinstance(data_key, DataKey):
        encryption_data_key = data_key
        _LOGGER.debug('full encryption data key provided')
    else:
        raise NotSupportedError('Unsupported data_key type: {}'.format(type(data_key)))
    _LOGGER.debug('encryption data key provider: %s', encryption_data_key.key_provider)
    for master_key in master_keys:
        encrypted_key = master_key.encrypt_data_key(
            data_key=encryption_data_key,
            algorithm=algorithm,
            encryption_context=encryption_context
        )
        encrypted_data_keys.add(encrypted_key)
        _LOGGER.debug('encryption key encrypted with master key: %s', master_key.key_provider)
        if master_key is primary_master_key:
            encrypted_encryption_data_key = encrypted_key
    # Normalize output to DataKey
    encryption_data_key = DataKey(
        key_provider=encryption_data_key.key_provider,
        data_key=encryption_data_key.data_key,
        encrypted_data_key=encrypted_encryption_data_key.encrypted_data_key
    )
    return encryption_data_key, encrypted_data_keys

try:
    _FILE_TYPE = file
except NameError:
    _FILE_TYPE = io.IOBase


def prep_stream_data(data):
    """Takes an input str, bytes, io.IOBase, or file object and returns an appropriate stream for _EncryptionStream objects.

    :param data: Input data
    :type data: str, bytes, io.IOBase, or file
    :returns: Prepared stream
    :rtype: io.BytesIO
    """
    if isinstance(data, (_FILE_TYPE, io.IOBase, six.StringIO)):
        return data
    return io.BytesIO(to_bytes(data))


def source_data_key_length_check(source_data_key, algorithm):
    """Validates that the supplied source_data_key's data_key is the
    correct length for the supplied algorithm's kdf_input_len value.

    :param source_data_key: Source data key object received from MasterKey decrypt or generate data_key methods
    :type source_data_key: :class:`aws_encryption_sdk.structure.RawDataKey`
        or :class:`aws_encryption_sdk.structure.DataKey`
    :param algorithm: Algorithm object which directs how this data key will be used
    :type algorithm: aws_encryption_sdk.internal.crypto.identifiers.Algorithm
    :raises InvalidDataKeyError: if data key length does not match required kdf input length
    """
    if len(source_data_key.data_key) != algorithm.kdf_input_len:
        raise InvalidDataKeyError('Invalid Source Data Key length {actual} for algorithm required: {required}'.format(
            actual=len(source_data_key.data_key),
            required=algorithm.kdf_input_len
        ))
