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

from aws_encryption_sdk.identifiers import AlgorithmSuite, ContentType, ObjectType, SerializationVersion
from aws_encryption_sdk.internal.str_ops import to_bytes, to_str


@attr.s(hash=True)
class MessageHeader(object):
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

    version = attr.ib(hash=True, validator=attr.validators.instance_of(SerializationVersion))
    type = attr.ib(hash=True, validator=attr.validators.instance_of(ObjectType))
    algorithm = attr.ib(hash=True, validator=attr.validators.instance_of(AlgorithmSuite))
    message_id = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    encryption_context = attr.ib(hash=True, validator=attr.validators.instance_of(dict))
    encrypted_data_keys = attr.ib(hash=True, validator=attr.validators.instance_of(set))
    content_type = attr.ib(hash=True, validator=attr.validators.instance_of(ContentType))
    content_aad_length = attr.ib(hash=True, validator=attr.validators.instance_of(six.integer_types))
    header_iv_length = attr.ib(hash=True, validator=attr.validators.instance_of(six.integer_types))
    frame_length = attr.ib(hash=True, validator=attr.validators.instance_of(six.integer_types))


@attr.s(hash=True)
class MasterKeyInfo(object):
    """Contains information necessary to identify a Master Key.

    :param str provider_id: MasterKey provider_id value
    :param bytes key_info: MasterKey key_info value
    """

    provider_id = attr.ib(hash=True, validator=attr.validators.instance_of((six.string_types, bytes)), converter=to_str)
    key_info = attr.ib(hash=True, validator=attr.validators.instance_of((six.string_types, bytes)), converter=to_bytes)


@attr.s(hash=True)
class RawDataKey(object):
    """Hold only the unencrypted copy of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structures.MasterKeyInfo
    :param bytes data_key: Plaintext data key
    """

    key_provider = attr.ib(hash=True, validator=attr.validators.instance_of(MasterKeyInfo))
    data_key = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))


@attr.s(hash=True)
class DataKey(object):
    """Holds both the encrypted and unencrypted copies of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structures.MasterKeyInfo
    :param bytes data_key: Plaintext data key
    :param bytes encrypted_data_key: Encrypted data key
    """

    key_provider = attr.ib(hash=True, validator=attr.validators.instance_of(MasterKeyInfo))
    data_key = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))
    encrypted_data_key = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))


@attr.s(hash=True)
class EncryptedDataKey(object):
    """Holds only the encrypted copy of a data key.

    :param key_provider: Key Provider information
    :type key_provider: aws_encryption_sdk.structures.MasterKeyInfo
    :param bytes encrypted_data_key: Encrypted data key
    """

    key_provider = attr.ib(hash=True, validator=attr.validators.instance_of(MasterKeyInfo))
    encrypted_data_key = attr.ib(hash=True, validator=attr.validators.instance_of(bytes))


@attr.s
class DataKeyMaterials(object):
    """Container for all values strongly tied to a single data key.

    .. versionadded:: 1.4.0

    :param AlgorithmSuite algorithm_suite: Algorithm suite that the data key must be used with
    :param dict[str, str] encryption_context: Encryption context that must be used with the data key
    :param RawDataKey plaintext_data_key: Data key plaintext
    :param set[EncryptedDataKey] encrypted_data_keys: Encrypted versions of the data key
    """

    _algorithm_suite = attr.ib(validator=attr.validators.instance_of(AlgorithmSuite))
    _encryption_context = attr.ib(validator=attr.validators.instance_of(dict), converter=copy.copy)
    _plaintext_data_key = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(RawDataKey)), default=None
    )
    _encrypted_data_keys = attr.ib(validator=attr.validators.instance_of(set), default=attr.Factory(set))

    @property
    def algorithm_suite(self):
        """Read-only access to the algorithm suite."""
        return self._algorithm_suite

    @property
    def encryption_context(self):
        """Get a copy of the encryption context."""
        return copy.copy(self._encryption_context)

    @property
    def plaintext_data_key(self):
        """Get a copy of the plaintext data key."""
        return copy.copy(self._plaintext_data_key)

    @plaintext_data_key.setter
    def plaintext_data_key(self, value):
        """Set the plaintext data key, but only if it is the correct length for the algorithm suite."""
        if len(value) != self.algorithm_suite.data_key_len:
            raise Exception(
                "TODO: " "Invalid data key length %d bytes for algorithm suite %s.",
                len(value),
                self.algorithm_suite.data_key_len,
            )

        self._plaintext_data_key = value

    @property
    def encrypted_data_keys(self):
        """Copy and freeze the encrypted data keys before providing them."""
        return frozenset(copy.copy(self._encrypted_data_keys))

    @encrypted_data_keys.setter
    def encrypted_data_keys(self, value):
        """Do not allow setting of the encrypted data keys directly."""
        raise Exception("TODO: " 'Encrypted data keys must be modified through the "add_encrypted_data_key" method.')

    def add_encrypted_data_key(self, encrypted_data_key):
        # type: (EncryptedDataKey) -> None
        """Add an encrypted data key, but only if the plaintext data key is set.

        :param EncryptedDataKey encrypted_data_key: Encrypted data key to add
        """
        if self._plaintext_data_key is None:
            raise Exception("TODO: " "Cannot add an encrypted data key when plaintext data key is not set")

        self._encrypted_data_keys.add(encrypted_data_key)
