"""
Components for handling serialization and deserialization of
encryption context data in AWS Encryption SDK messages.
"""
import codecs
import logging
import struct

from aws_encryption_sdk.exceptions import SerializationError
import aws_encryption_sdk.internal.defaults
import aws_encryption_sdk.identifiers
import aws_encryption_sdk.internal.str_ops

_LOGGER = logging.getLogger(__name__)


def assemble_content_aad(message_id, aad_content_string, seq_num, length):
    """Assembles the Body AAD string for a message body structure.

    :param message_id: Message ID
    :type message_id: str
    :param aad_content_string: ContentAADString object for frame type
    :type aad_content_string: aws_encryption_sdk.identifiers.ContentAADString
    :param seq_num: Sequence number of frame
    :type seq_num: int
    :param length: Content Length
    :type length: int
    :returns: Properly formatted AAD string for message body structure.
    :rtype: bytes
    :raises SerializationError: if aad_content_string is not known
    """
    if not isinstance(aad_content_string, aws_encryption_sdk.identifiers.ContentAADString):
        raise SerializationError('Unknown aad_content_string')
    fmt = '>16s{}sIQ'.format(len(aad_content_string.value))
    return struct.pack(fmt, message_id, aad_content_string.value, seq_num, length)


def serialize_encryption_context(encryption_context):
    """Serializes the contents of a dictionary into a byte string.

    :param dict encryption_context: Dictionary of encrytion context keys/values.
    :returns: Serialized encryption context
    :rtype: bytes
    """
    if not encryption_context:
        return bytes()

    serialized_context = bytearray()
    dict_size = len(encryption_context)

    if dict_size > aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE:
        raise SerializationError('The encryption context contains too many elements.')

    serialized_context.extend(struct.pack('>H', dict_size))

    # Encode strings first to catch bad values.
    encryption_context_list = []
    for key, value in encryption_context.items():
        try:
            if isinstance(key, bytes):
                key = codecs.decode(key)
            if isinstance(value, bytes):
                value = codecs.decode(value)
            encryption_context_list.append((
                aws_encryption_sdk.internal.str_ops.to_bytes(key),
                aws_encryption_sdk.internal.str_ops.to_bytes(value)
            ))
        except Exception:
            raise SerializationError(
                'Cannot encode dictionary key or value using {}.'.format(
                    aws_encryption_sdk.internal.defaults.ENCODING
                )
            )

    for key, value in sorted(encryption_context_list, key=lambda x: x[0]):
        serialized_context.extend(struct.pack(
            '>H{key_size}sH{value_size}s'.format(
                key_size=len(key),
                value_size=len(value)
            ),
            len(key),
            key,
            len(value),
            value
        ))
        if len(serialized_context) > aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE:
            raise SerializationError('The serialized context is too large.')
    return bytes(serialized_context)


def read_short(source, offset):
    """Reads a number from a byte array.

    :param bytes source: Source byte string
    :param int offset: Point in byte string to start reading
    :returns: Read number and offset at point after read data
    :rtype: tuple of ints
    :raises: SerializationError if unable to unpack
    """
    try:
        (short,) = struct.unpack_from('>H', source, offset)
        return short, offset + struct.calcsize('>H')
    except struct.error:
        raise SerializationError('Bad format of serialized context.')


def read_string(source, offset, length):
    """Reads a string from a byte string.

    :param bytes source: Source byte string
    :param int offset: Point in byte string to start reading
    :param int length: Length of string to read
    :returns: Read string and offset at point after read data
    :rtype: tuple of str and int
    :raises SerializationError: if unable to unpack
    """
    end = offset + length
    try:
        return (
            codecs.decode(source[offset:end], aws_encryption_sdk.internal.defaults.ENCODING),
            end
        )
    except Exception:
        raise SerializationError('Bad format of serialized context.')


def deserialize_encryption_context(serialized_encryption_context):
    """Deserializes the contents of a byte string into a dictionary.

    :param bytes serialized_encryption_context: Source byte string containing serialized dictionary
    :returns: Deserialized encryption context
    :rtype: dict
    :raises SerializationError: if serialized encryption context is too large
    :raises SerializationError: if duplicate key found in serialized encryption context
    :raises SerializationError: if malformed data found in serialized encryption context
    """
    if len(serialized_encryption_context) > aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE:
        raise SerializationError('Serialized context is too long.')

    if serialized_encryption_context == b'':
        _LOGGER.debug('No encryption context data found')
        return {}

    deserialized_size = 0
    encryption_context = {}

    dict_size, deserialized_size = read_short(
        source=serialized_encryption_context,
        offset=deserialized_size
    )
    _LOGGER.debug('Found %s keys', dict_size)
    for _ in range(dict_size):
        key_size, deserialized_size = read_short(
            source=serialized_encryption_context,
            offset=deserialized_size
        )
        key, deserialized_size = read_string(
            source=serialized_encryption_context,
            offset=deserialized_size,
            length=key_size
        )
        value_size, deserialized_size = read_short(
            source=serialized_encryption_context,
            offset=deserialized_size
        )
        value, deserialized_size = read_string(
            source=serialized_encryption_context,
            offset=deserialized_size,
            length=value_size
        )
        if key in encryption_context:
            raise SerializationError('Duplicate key in serialized context.')
        encryption_context[key] = value

    if deserialized_size != len(serialized_encryption_context):
        raise SerializationError('Formatting error: Extra data in serialized context.')

    return encryption_context
