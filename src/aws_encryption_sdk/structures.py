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
"""Public data structures for aws_encryption_sdk."""
import copy

import attr
import six
from attr.validators import deep_iterable, deep_mapping, instance_of, optional

from aws_encryption_sdk.identifiers import Algorithm, ContentType, KeyringTraceFlag, ObjectType, SerializationVersion
from aws_encryption_sdk.internal.str_ops import to_bytes, to_str


@attr.s(hash=True)
class MasterKeyInfo(object):
    """Contains information necessary to identify a Master Key.

    ``key_id`` is optional because ``key_id`` and ``key_info`` SHOULD
    always be the same except in the case of the Raw AES Keyring/MasterKey.
    This gives the option to specify a different ``key_id`` value if needed.

    :param str provider_id: MasterKey provider_id value
    :param bytes key_info: MasterKey key_info value
    :param bytes key_id: MasterKey key_id value (optional)
    """

    provider_id = attr.ib(hash=True, validator=instance_of((six.string_types, bytes)), converter=to_str)
    key_info = attr.ib(hash=True, validator=instance_of((six.string_types, bytes)), converter=to_bytes)
    _key_id = attr.ib(
        hash=True,
        eq=False,
        default=None,
        validator=optional(instance_of((six.string_types, bytes))),
        converter=to_bytes,
    )

    @property
    def key_id(self):
        """Return the key ID if separately specified, or the key info if not."""
        if self._key_id is None:
            return self.key_info

        return self._key_id


@attr.s(hash=True)
class RawDataKey(object):
    """Hold only the unencrypted copy of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structures.MasterKeyInfo
    :param bytes data_key: Plaintext data key
    """

    key_provider = attr.ib(hash=True, validator=instance_of(MasterKeyInfo))
    data_key = attr.ib(hash=True, repr=False, validator=instance_of(bytes))

    @classmethod
    def from_data_key(cls, data_key):
        # type: (DataKey) -> RawDataKey
        """Build an :class:`RawDataKey` from a :class:`DataKey`.

        .. versionadded:: 1.5.0
        """
        if not isinstance(data_key, DataKey):
            raise TypeError("data_key must be type DataKey not {}".format(type(data_key).__name__))

        return RawDataKey(key_provider=copy.copy(data_key.key_provider), data_key=copy.copy(data_key.data_key))


@attr.s(hash=True)
class DataKey(object):
    """Holds both the encrypted and unencrypted copies of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structures.MasterKeyInfo
    :param bytes data_key: Plaintext data key
    :param bytes encrypted_data_key: Encrypted data key
    """

    key_provider = attr.ib(hash=True, validator=instance_of(MasterKeyInfo))
    data_key = attr.ib(hash=True, repr=False, validator=instance_of(bytes))
    encrypted_data_key = attr.ib(hash=True, validator=instance_of(bytes))


@attr.s(hash=True)
class EncryptedDataKey(object):
    """Holds only the encrypted copy of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structures.MasterKeyInfo
    :param bytes encrypted_data_key: Encrypted data key
    """

    key_provider = attr.ib(hash=True, validator=instance_of(MasterKeyInfo))
    encrypted_data_key = attr.ib(hash=True, validator=instance_of(bytes))

    @classmethod
    def from_data_key(cls, data_key):
        # type: (DataKey) -> EncryptedDataKey
        """Build an :class:`EncryptedDataKey` from a :class:`DataKey`.

        .. versionadded:: 1.5.0
        """
        if not isinstance(data_key, DataKey):
            raise TypeError("data_key must be type DataKey not {}".format(type(data_key).__name__))

        return EncryptedDataKey(
            key_provider=copy.copy(data_key.key_provider), encrypted_data_key=copy.copy(data_key.encrypted_data_key)
        )


@attr.s
class KeyringTrace(object):
    """Record of all actions that a KeyRing performed with a wrapping key.

    .. versionadded:: 1.5.0

    :param MasterKeyInfo wrapping_key: Wrapping key used
    :param flags: Actions performed
    :type flags: set of :class:`KeyringTraceFlag`
    """

    wrapping_key = attr.ib(validator=instance_of(MasterKeyInfo))
    flags = attr.ib(validator=deep_iterable(member_validator=instance_of(KeyringTraceFlag)))


@attr.s(hash=True)
class MessageHeader(object):
    # pylint: disable=too-many-instance-attributes
    """Deserialized message header object.

    :param version: Message format version, per spec
    :type version: SerializationVersion
    :param type: Message content type, per spec
    :type type: ObjectType
    :param algorithm: Algorithm to use for encryption
    :type algorithm: Algorithm
    :param bytes message_id: Message ID
    :param dict encryption_context: Dictionary defining encryption context
    :param encrypted_data_keys: Encrypted data keys
    :type encrypted_data_keys: set of :class:`aws_encryption_sdk.structures.EncryptedDataKey`
    :param content_type: Message content framing type (framed/non-framed)
    :type content_type: ContentType
    :param bytes content_aad_length: empty
    :param int header_iv_length: Bytes in Initialization Vector value found in header
    :param int frame_length: Length of message frame in bytes
    """

    version = attr.ib(hash=True, validator=instance_of(SerializationVersion))
    type = attr.ib(hash=True, validator=instance_of(ObjectType))
    algorithm = attr.ib(hash=True, validator=instance_of(Algorithm))
    message_id = attr.ib(hash=True, validator=instance_of(bytes))
    encryption_context = attr.ib(
        hash=True,
        validator=deep_mapping(
            key_validator=instance_of(six.string_types), value_validator=instance_of(six.string_types)
        ),
    )
    encrypted_data_keys = attr.ib(hash=True, validator=deep_iterable(member_validator=instance_of(EncryptedDataKey)))
    content_type = attr.ib(hash=True, validator=instance_of(ContentType))
    content_aad_length = attr.ib(hash=True, validator=instance_of(six.integer_types))
    header_iv_length = attr.ib(hash=True, validator=instance_of(six.integer_types))
    frame_length = attr.ib(hash=True, validator=instance_of(six.integer_types))
