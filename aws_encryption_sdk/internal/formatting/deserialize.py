"""Components for handling AWS Encryption SDK message deserialization."""
from __future__ import division
import logging
import struct

from cryptography.exceptions import InvalidTag

from aws_encryption_sdk.exceptions import SerializationError, UnknownIdentityError, NotSupportedError
import aws_encryption_sdk.internal.crypto
from aws_encryption_sdk.internal.formatting.encryption_context import deserialize_encryption_context
from aws_encryption_sdk.identifiers import (
    Algorithm, ObjectType, SerializationVersion, ContentType, SequenceIdentifier
)
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.internal.structures import (
    MessageHeaderAuthentication, MessageFrameBody,
    MessageFooter, EncryptedData
)
from aws_encryption_sdk.structures import MasterKeyInfo, MessageHeader, EncryptedDataKey

_LOGGER = logging.getLogger(__name__)


def verifier_from_header(header):
    """Builds a verifier from a header.

    :param header: Header from which to build verifier
    :type header: aws_encryption_sdk.structure.MessageHeader
    :returns: verifier built from information in header
    :rtype: aws_encryption_sdk.internal.crypto.Verifier
    :raises SerializationError: if no public key is found in header for ECDSA algorithm
    """
    encoded_point = header.encryption_context.get(
        aws_encryption_sdk.internal.defaults.ENCODED_SIGNER_KEY,
        None
    )
    if encoded_point is None:
        if header.algorithm.signing_algorithm_info is None:
            verifier = None
        else:
            raise SerializationError(
                'No public key found in header for message encrypted with ECDSA algorithm: {}'.format(
                    header.algorithm.name
                )
            )
    else:
        verifier = aws_encryption_sdk.internal.crypto.Verifier.from_encoded_point(
            algorithm=header.algorithm,
            encoded_point=encoded_point
        )
    return verifier


def validate_header(header, header_auth, stream, header_start, header_end, data_key):
    """Validates the header using the header authentication data.

    :param header: Deserialized header
    :type header: aws_encryption_sdk.structure.MessageHeader
    :param header_auth: Deserialized header auth
    :type header_auth: aws_encryption_sdk.internal.structures.MessageHeaderAuthentication
    :param stream: Stream containing serialized message
    :type stream: io.BytesIO
    :param int header_start: Position in stream of start of serialized header
    :param int header_end: Position in stream of end of serialized header
    :param data_key: Data key with which to perform validation
    :type data_key: aws_encryption_sdk.structure.DataKey
    :raises SerializationError: if header authorization fails
    """
    _LOGGER.debug('Starting header validation')
    current_position = stream.tell()
    stream.seek(header_start)
    try:
        aws_encryption_sdk.internal.crypto.decrypt(
            algorithm=header.algorithm,
            key=data_key.data_key,
            encrypted_data=EncryptedData(header_auth.iv, b'', header_auth.tag),
            associated_data=stream.read(header_end - header_start),
            message_id=header.message_id
        )
    except InvalidTag:
        raise SerializationError('Header authorization failed')
    stream.seek(current_position)


def deserialize_header(stream):
    """Deserializes the header from a source stream

    :param stream: Source data stream
    :type stream: io.BytesIO
    :returns: Deserialized MessageHeader object
    :rtype: aws_encryption_sdk.structure.MessageHeader
    :raises NotSupportedError: if unsupported data types are found
    :raises UnknownIdentityError: if unknown data types are found
    :raises SerializationError: if IV length does not match algorithm
    """
    _LOGGER.debug('Starting header deserialization')
    version_id, message_type_id = unpack_values('>BB', stream)
    try:
        message_type = ObjectType(message_type_id)
    except ValueError as e:
        raise NotSupportedError(
            'Unsupported type {} discovered in data stream'.format(message_type_id),
            e
        )
    try:
        version = SerializationVersion(version_id)
    except ValueError as e:
        raise NotSupportedError('Unsupported version {}'.format(version_id), e)
    header = {'version': version, 'type': message_type}

    algorithm_id, message_id, ser_encryption_context_length = unpack_values('>H16sH', stream)

    try:
        alg = Algorithm.get_by_id(algorithm_id)
    except KeyError as e:
        raise UnknownIdentityError('Unknown algorithm {}'.format(algorithm_id), e)
    if not alg.allowed:
        raise NotSupportedError('Unsupported algorithm: {}'.format(alg))
    header['algorithm'] = alg
    header['message_id'] = message_id

    header['encryption_context'] = deserialize_encryption_context(
        stream.read(ser_encryption_context_length)
    )
    (encrypted_data_key_count,) = unpack_values('>H', stream)

    encrypted_data_keys = set([])
    for _ in range(encrypted_data_key_count):
        (key_provider_length,) = unpack_values('>H', stream)
        (key_provider_identifier,) = unpack_values(
            '>{}s'.format(key_provider_length),
            stream
        )
        (key_provider_information_length,) = unpack_values('>H', stream)
        (key_provider_information,) = unpack_values(
            '>{}s'.format(key_provider_information_length),
            stream
        )
        (encrypted_data_key_length,) = unpack_values('>H', stream)
        encrypted_data_key = stream.read(encrypted_data_key_length)
        encrypted_data_keys.add(EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id=to_str(key_provider_identifier),
                key_info=key_provider_information
            ),
            encrypted_data_key=encrypted_data_key
        ))
    header['encrypted_data_keys'] = encrypted_data_keys

    (content_type_id,) = unpack_values('>B', stream)
    try:
        content_type = ContentType(content_type_id)
    except ValueError as e:
        raise UnknownIdentityError(
            'Unknown content type {}'.format(content_type_id),
            e
        )
    header['content_type'] = content_type

    (content_aad_length,) = unpack_values('>I', stream)
    if content_aad_length != 0:
        raise SerializationError(
            'Content AAD length field is currently unused, its value must be always 0'
        )
    header['content_aad_length'] = 0

    (iv_length,) = unpack_values('>B', stream)
    if iv_length != alg.iv_len:
        raise SerializationError(
            'Specified IV length ({length}) does not match algorithm IV length ({alg})'.format(
                length=iv_length,
                alg=alg
            )
        )
    header['header_iv_length'] = iv_length

    (frame_length,) = unpack_values('>I', stream)
    if content_type == ContentType.FRAMED_DATA and frame_length > aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE:
        raise SerializationError('Specified frame length larger than allowed maximum: {found} > {max}'.format(
            found=frame_length,
            max=aws_encryption_sdk.internal.defaults.MAX_FRAME_SIZE
        ))
    elif content_type == ContentType.NO_FRAMING and frame_length != 0:
        raise SerializationError('Non-zero frame length found for non-framed message')
    header['frame_length'] = frame_length

    return MessageHeader(**header)


def deserialize_header_auth(stream, algorithm, verifier=None):
    """Deserializes a MessageHeaderAuthentication object from a source stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param algorithm: The Algorithm object type contained in the header
    :type algorith: aws_encryption_sdk.identifiers.Algorithm
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Deserialized MessageHeaderAuthentication object
    :rtype: aws_encryption_sdk.internal.structures.MessageHeaderAuthentication
    """
    _LOGGER.debug('Starting header auth deserialization')
    format_string = '>{iv_len}s{tag_len}s'.format(
        iv_len=algorithm.iv_len,
        tag_len=algorithm.tag_len
    )
    return MessageHeaderAuthentication(*unpack_values(format_string, stream, verifier))


def deserialize_non_framed_values(stream, header, verifier=None):
    """Deserializes the IV and Tag from a non-framed stream.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param header: Deserialized header
    :type header: aws_encryption_sdk.structure.MessageHeader
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: IV, Tag, and Data Length values for body
    :rtype: tuple of str, str, and int
    """
    _LOGGER.debug('Starting non-framed body iv/tag deserialization')
    (data_iv, data_length) = unpack_values(
        '>{}sQ'.format(header.algorithm.iv_len),
        stream,
        verifier
    )
    body_start = stream.tell()
    stream.seek(data_length, 1)
    (data_tag,) = unpack_values(
        format_string='>{auth_len}s'.format(auth_len=header.algorithm.auth_len),
        stream=stream,
        verifier=None
    )
    stream.seek(body_start, 0)
    return data_iv, data_tag, data_length


def update_verifier_with_tag(stream, header, verifier):
    """Updates verifier with data for authentication tag.

    .. note::
        This is meant to be used in conjunction with deserialize_non_framed_values
        to update the verifier over information which has already been retrieved.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param header: Deserialized header
    :type header: aws_encryption_sdk.structure.MessageHeader
    :param verifier: Signature verifier object
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Data authentication tag value
    :rtype: str
    """
    return unpack_values(
        '>{auth_len}s'.format(auth_len=header.algorithm.auth_len),
        stream,
        verifier
    )


def deserialize_frame(stream, header, verifier=None):
    """Deserializes a frame from a body.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param header: Deserialized header
    :type header: aws_encryption_sdk.structure.MessageHeader
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Deserialized frame and a boolean stating if this is the final frame
    :rtype: :class:`aws_encryption_sdk.internal.structures.MessageFrameBody` and bool
    """
    _LOGGER.debug('Starting frame deserialization')
    frame_data = {}
    final_frame = False
    (sequence_number,) = unpack_values('>I', stream, verifier)
    if sequence_number == SequenceIdentifier.SEQUENCE_NUMBER_END.value:
        _LOGGER.debug('Deserializing final frame')
        (sequence_number,) = unpack_values('>I', stream, verifier)
        final_frame = True
    else:
        _LOGGER.debug('Deserializing frame sequence number %s', int(sequence_number))
    frame_data['final_frame'] = final_frame
    frame_data['sequence_number'] = sequence_number
    (frame_iv,) = unpack_values(
        '>{iv_len}s'.format(iv_len=header.algorithm.iv_len),
        stream,
        verifier
    )
    frame_data['iv'] = frame_iv
    if final_frame is True:
        (content_length,) = unpack_values('>I', stream, verifier)
        if content_length >= header.frame_length:
            raise SerializationError('Invalid final frame length: {final} >= {normal}'.format(
                final=content_length,
                normal=header.frame_length
            ))
    else:
        content_length = header.frame_length
    (frame_content, frame_tag) = unpack_values(
        '>{content_len}s{auth_len}s'.format(
            content_len=content_length,
            auth_len=header.algorithm.auth_len
        ),
        stream,
        verifier
    )
    frame_data['ciphertext'] = frame_content
    frame_data['tag'] = frame_tag
    return MessageFrameBody(**frame_data), final_frame


def deserialize_footer(stream, verifier=None):
    """Deserializes a footer.

    :param stream: Source data stream
    :type stream: io.BytesIO
    :param verifier: Signature verifier object (optional)
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Deserialized footer
    :rtype: aws_encryption_sdk.internal.structures.MessageFooter
    :raises SerializationError: if verifier supplied and no footer found
    """
    _LOGGER.debug('Starting footer deserialization')
    signature = b''
    if verifier is None:
        return MessageFooter(signature=signature)
    try:
        (sig_len,) = unpack_values('>H', stream)
        (signature,) = unpack_values(
            '>{sig_len}s'.format(sig_len=sig_len),
            stream
        )
    except SerializationError:
        raise SerializationError('No signature found in message')
    if verifier:
        verifier.set_signature(signature)
        verifier.verify()
    return MessageFooter(signature=signature)


def unpack_values(format_string, stream, verifier=None):
    """Helper function to unpack struct data from a stream and update the signature verifier.

    :param format_string: Struct format string
    :type format_string: str
    :param stream: Source data stream
    :type stream: io.BytesIO
    :param verifier: Signature verifier object
    :type verifier: aws_encryption_sdk.internal.crypto.Verifier
    :returns: Unpacked values
    :rtype: tuple
    """
    try:
        message_bytes = stream.read(struct.calcsize(format_string))
        if verifier:
            verifier.update(message_bytes)
        values = struct.unpack(format_string, message_bytes)
    except struct.error as e:
        raise SerializationError('Unexpected deserialization error', type(e), e.args)
    return values


def deserialize_wrapped_key(wrapping_algorithm, wrapping_key_id, wrapped_encrypted_key):
    """Extracts and deserializes EncryptedData from a Wrapped EncryptedDataKey.

    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext_data_key
    :type wrapping_algorithm: aws_encryption_sdk.identifiers.WrappingAlgorithm
    :param str wrapping_key_id: Key ID of wrapping MasterKey
    :param wrapped_encrypted_key: Raw Wrapped EncryptedKey
    :type wrapped_encrypted_key: aws_encryption_sdk.structure.EncryptedDataKey
    :returns: EncryptedData of deserialized Wrapped EncryptedKey
    :rtype: aws_encryption_sdk.internal.structures.EncryptedData
    :raises SerializationError: if wrapping_key_id does not match deserialized wrapping key id
    :raises SerializationError: if wrapping_algorithm IV length does not match deserialized IV length
    """
    if wrapping_key_id == wrapped_encrypted_key.key_provider.key_info:
        encrypted_wrapped_key = EncryptedData(
            iv=None,
            ciphertext=wrapped_encrypted_key.encrypted_data_key,
            tag=None
        )
    else:
        if not wrapped_encrypted_key.key_provider.key_info.startswith(wrapping_key_id):
            raise SerializationError('Master Key mismatch for wrapped data key')
        _key_info = wrapped_encrypted_key.key_provider.key_info[len(wrapping_key_id):]
        try:
            tag_len, iv_len = struct.unpack('>II', _key_info[:8])
        except struct.error:
            raise SerializationError('Malformed key info: key info missing data')
        tag_len //= 8  # Tag Length is stored in bits, not bytes
        if iv_len != wrapping_algorithm.algorithm.iv_len:
            raise SerializationError('Wrapping Algorithm mismatch for wrapped data key')
        iv = _key_info[8:]
        if len(iv) != iv_len:
            raise SerializationError('Malformed key info: incomplete iv')
        ciphertext = wrapped_encrypted_key.encrypted_data_key[:-1 * tag_len]
        tag = wrapped_encrypted_key.encrypted_data_key[-1 * tag_len:]
        if not ciphertext or len(tag) != tag_len:
            raise SerializationError('Malformed key info: incomplete ciphertext or tag')
        encrypted_wrapped_key = EncryptedData(
            iv=iv,
            ciphertext=ciphertext,
            tag=tag
        )
    return encrypted_wrapped_key
