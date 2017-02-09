"""Public data structures for aws_encryption_sdk."""
import attr
import six

import aws_encryption_sdk.identifiers
from aws_encryption_sdk.internal.str_ops import to_str, to_bytes


@attr.s
class MessageHeader(object):
    """Deserialized message header object.

    :param version: Message format version, per spec
    :type version: aws_encryption_sdk.identifiers.SerializationVersion
    :param type: Message content type, per spec
    :type type: aws_encryption_sdk.identifiers.ObjectType
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes message_id: Message ID
    :param dict encryption_context: Dictionary defining encryption context
    :param encrypted_data_keys: Encrypted data keys
    :type encrypted_data_keys: set of :class:`aws_encryption_sdk.structure.EncryptedDataKey`
    :param content_type: Message content framing type (framed/non-framed)
    :type content_type: aws_encryption_sdk.identifiers.ContentType
    :param bytes content_aad_length: empty
    :param int header_iv_length: Bytes in Initialization Vector value found in header
    :param int frame_length: Length of message frame in bytes
    """
    version = attr.ib(validator=attr.validators.instance_of(
        aws_encryption_sdk.identifiers.SerializationVersion
    ))
    type = attr.ib(validator=attr.validators.instance_of(
        aws_encryption_sdk.identifiers.ObjectType
    ))
    algorithm = attr.ib(validator=attr.validators.instance_of(
        aws_encryption_sdk.identifiers.Algorithm
    ))
    message_id = attr.ib(validator=attr.validators.instance_of(bytes))
    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    encrypted_data_keys = attr.ib(validator=attr.validators.instance_of(set))
    content_type = attr.ib(validator=attr.validators.instance_of(
        aws_encryption_sdk.identifiers.ContentType
    ))
    content_aad_length = attr.ib(validator=attr.validators.instance_of(int))
    header_iv_length = attr.ib(validator=attr.validators.instance_of(int))
    frame_length = attr.ib(validator=attr.validators.instance_of(int))


@attr.s
class MasterKeyInfo(object):
    """Contains information necessary to identify a Master Key.

    :param str provider_id: MasterKey provider_id value
    :param bytes key_info: MasterKey key_info value
    """
    provider_id = attr.ib(
        validator=attr.validators.instance_of((six.string_types, bytes)),
        convert=to_str
    )
    key_info = attr.ib(
        validator=attr.validators.instance_of((six.string_types, bytes)),
        convert=to_bytes
    )


@attr.s
class RawDataKey(object):
    """Hold only the unencrypted copy of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structure.MasterKeyInfo
    :param bytes data_key: Plaintext data key
    """
    key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyInfo))
    data_key = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s
class DataKey(object):
    """Holds both the encrypted and unencrypted copies of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structure.MasterKeyInfo
    :param bytes data_key: Plaintext data key
    :param bytes encrypted_data_key: Encrypted data key
    """
    key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyInfo))
    data_key = attr.ib(validator=attr.validators.instance_of(bytes))
    encrypted_data_key = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s
class EncryptedDataKey(object):
    """Holds only the encrypted copy of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structure.MasterKeyInfo
    :param bytes encrypted_data_key: Encrypted data key
    """
    key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyInfo))
    encrypted_data_key = attr.ib(validator=attr.validators.instance_of(bytes))
