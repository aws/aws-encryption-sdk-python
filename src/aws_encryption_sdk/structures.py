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

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Tuple  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


@attr.s(hash=True)
class MasterKeyInfo(object):
    """Contains information necessary to identify a Master Key.

    .. notice::

        The only keyring or master key that should need to set ``key_name`` is the Raw AES keyring/master key.
        For all other keyrings and master keys, ``key_info`` and ``key_name`` should always be the same.


    .. versionadded:: 1.5.0
        ``key_name``

    :param str provider_id: MasterKey provider_id value
    :param bytes key_info: MasterKey key_info value
    :param bytes key_name: Key name if different than key_info (optional)
    """

    provider_id = attr.ib(hash=True, validator=instance_of((six.string_types, bytes)), converter=to_str)
    key_info = attr.ib(hash=True, validator=instance_of((six.string_types, bytes)), converter=to_bytes)
    key_name = attr.ib(
        hash=True, default=None, validator=optional(instance_of((six.string_types, bytes))), converter=to_bytes
    )

    def __attrs_post_init__(self):
        """Set ``key_name`` if not already set."""
        if self.key_name is None:
            self.key_name = self.key_info

    @property
    def key_namespace(self):
        """Access the key namespace value (previously, provider ID).

        .. versionadded:: 1.5.0

        """
        return self.provider_id


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
    :param Set[KeyringTraceFlag] flags: Actions performed
    """

    wrapping_key = attr.ib(validator=instance_of(MasterKeyInfo))
    flags = attr.ib(validator=deep_iterable(member_validator=instance_of(KeyringTraceFlag)))


@attr.s(hash=True)
class MessageHeader(object):
    # pylint: disable=too-many-instance-attributes
    """Deserialized message header object.

    :param SerializationVersion version: Message format version, per spec
    :param ObjectType type: Message content type, per spec
    :param AlgorithmSuite algorithm: Algorithm to use for encryption
    :param bytes message_id: Message ID
    :param Dict[str,str] encryption_context: Dictionary defining encryption context
    :param Sequence[EncryptedDataKey] encrypted_data_keys: Encrypted data keys
    :param ContentType content_type: Message content framing type (framed/non-framed)
    :param int content_aad_length: empty
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


@attr.s
class CryptoResult(object):
    """Result container for one-shot cryptographic API results.

    .. versionadded:: 1.5.0

    .. note::

        For backwards compatibility,
        this container also unpacks like a 2-member tuple.
        This allows for backwards compatibility with the previous outputs.

    :param bytes result: Binary results of the cryptographic operation
    :param MessageHeader header: Encrypted message metadata
    :param Tuple[KeyringTrace] keyring_trace: Keyring trace entries
    """

    result = attr.ib(validator=instance_of(bytes))
    header = attr.ib(validator=instance_of(MessageHeader))
    keyring_trace = attr.ib(validator=deep_iterable(member_validator=instance_of(KeyringTrace)))

    def __attrs_post_init__(self):
        """Construct the inner tuple for backwards compatibility."""
        self._legacy_container = (self.result, self.header)

    def __len__(self):
        """Emulate the inner tuple."""
        return self._legacy_container.__len__()

    def __iter__(self):
        """Emulate the inner tuple."""
        return self._legacy_container.__iter__()

    def __getitem__(self, key):
        """Emulate the inner tuple."""
        return self._legacy_container.__getitem__(key)
