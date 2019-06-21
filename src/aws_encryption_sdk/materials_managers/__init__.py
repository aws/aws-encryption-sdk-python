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
"""Primitive structures for use when interacting with crypto material managers.

.. versionadded:: 1.3.0
"""
import attr
import six
from attr.validators import deep_iterable, deep_mapping, instance_of, optional

from ..identifiers import Algorithm, KeyRingTraceFlag
from ..internal.utils.streams import ROStream
from ..structures import DataKey, EncryptedDataKey, KeyRingTrace


@attr.s(hash=False)
class EncryptionMaterialsRequest(object):
    """Request object to provide to a crypto material manager's `get_encryption_materials` method.

    .. versionadded:: 1.3.0

    .. warning::
        If plaintext_rostream seek position is modified, it must be returned before leaving method.

    :param dict encryption_context: Encryption context passed to underlying master key provider and master keys
    :param int frame_length: Frame length to be used while encrypting stream
    :param plaintext_rostream: Source plaintext read-only stream (optional)
    :type plaintext_rostream: aws_encryption_sdk.internal.utils.streams.ROStream
    :param algorithm: Algorithm passed to underlying master key provider and master keys (optional)
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int plaintext_length: Length of source plaintext (optional)
    """

    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    frame_length = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    plaintext_rostream = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(ROStream))
    )
    algorithm = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(Algorithm)))
    plaintext_length = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )


@attr.s
class CryptographicMaterials(object):
    """Cryptographic materials core.

    .. versionadded:: 1.5.0

    :param Algorithm algorithm: Algorithm to use for encrypting message
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param DataKey data_encryption_key: Plaintext data key to use for encrypting message
    :param encrypted_data_keys: List of encrypted data keys
    :type encrypted_data_keys: list of :class:`EncryptedDataKey`
    :param keyring_trace: Any KeyRing trace entries
    :type keyring_trace: list of :class:`KeyRingTrace`
    """

    algorithm = attr.ib(validator=optional(instance_of(Algorithm)))
    encryption_context = attr.ib(
        validator=optional(
            deep_mapping(key_validator=instance_of(six.string_types), value_validator=instance_of(six.string_types))
        )
    )
    data_encryption_key = attr.ib(default=None, validator=optional(instance_of(DataKey)))
    encrypted_data_keys = attr.ib(
        default=attr.Factory(list), validator=optional(deep_iterable(member_validator=instance_of(EncryptedDataKey)))
    )
    keyring_trace = attr.ib(
        default=attr.Factory(list), validator=optional(deep_iterable(member_validator=instance_of(KeyRingTrace)))
    )


@attr.s(hash=False, init=False)
class EncryptionMaterials(CryptographicMaterials):
    """Encryption materials returned by a crypto material manager's `get_encryption_materials` method.

    .. versionadded:: 1.3.0

    .. versionadded:: 1.5.0

        The **keyring_trace** parameter.

    .. versionadded:: 1.5.0

        Most parameters are now optional.

    :param Algorithm algorithm: Algorithm to use for encrypting message
    :param DataKey data_encryption_key: Plaintext data key to use for encrypting message (optional)
    :param encrypted_data_keys: List of encrypted data keys (optional)
    :type encrypted_data_keys: list of :class:`EncryptedDataKey`
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param bytes signing_key: Encoded signing key (optional)
    :param keyring_trace: Any KeyRing trace entries (optional)
    :type keyring_trace: list of :class:`KeyRingTrace`
    """

    signing_key = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))

    def __init__(
        self,
        algorithm=None,
        data_encryption_key=None,
        encrypted_data_keys=None,
        encryption_context=None,
        signing_key=None,
        **kwargs
    ):
        if algorithm is None:
            raise TypeError("algorithm must not be None")

        if encryption_context is None:
            raise TypeError("encryption_context must not be None")

        super(EncryptionMaterials, self).__init__(
            algorithm=algorithm,
            encryption_context=encryption_context,
            data_encryption_key=data_encryption_key,
            encrypted_data_keys=encrypted_data_keys,
            **kwargs
        )
        self.signing_key = signing_key
        attr.validate(self)


@attr.s(hash=False)
class DecryptionMaterialsRequest(object):
    """Request object to provide to a crypto material manager's `decrypt_materials` method.

    .. versionadded:: 1.3.0

    :param algorithm: Algorithm to provide to master keys for underlying decrypt requests
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param encrypted_data_keys: Set of encrypted data keys
    :type encrypted_data_keys: set of `aws_encryption_sdk.structures.EncryptedDataKey`
    :param dict encryption_context: Encryption context to provide to master keys for underlying decrypt requests
    """

    algorithm = attr.ib(validator=attr.validators.instance_of(Algorithm))
    encrypted_data_keys = attr.ib(validator=attr.validators.instance_of(set))
    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))


_DEFAULT_SENTINEL = object()


@attr.s(hash=False, init=False)
class DecryptionMaterials(CryptographicMaterials):
    """Decryption materials returned by a crypto material manager's `decrypt_materials` method.

    .. versionadded:: 1.3.0

    .. versionadded:: 1.5.0

        The **algorithm**, **data_encryption_key**, **encrypted_data_keys**,
        **encryption_context**, and **keyring_trace** parameters.

    .. versionadded:: 1.5.0

        All parameters are now optional.

    :param Algorithm algorithm: Algorithm to use for encrypting message (optional)
    :param DataKey data_encryption_key: Plaintext data key to use for encrypting message (optional)
    :param encrypted_data_keys: List of encrypted data keys (optional)
    :type encrypted_data_keys: list of :class:`EncryptedDataKey`
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys` (optional)
    :param bytes verification_key: Raw signature verification key (optional)
    :param keyring_trace: Any KeyRing trace entries (optional)
    :type keyring_trace: list of :class:`KeyRingTrace`
    """

    verification_key = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))

    def __init__(self, data_key=_DEFAULT_SENTINEL, verification_key=None, **kwargs):
        if any(
            (
                data_key is _DEFAULT_SENTINEL and "data_encryption_key" not in kwargs,
                data_key is not _DEFAULT_SENTINEL and "data_encryption_key" in kwargs,
            )
        ):
            raise TypeError("Exactly one of data_key or data_encryption_key must be set")

        if data_key is not _DEFAULT_SENTINEL and "data_encryption_key" not in kwargs:
            kwargs["data_encryption_key"] = data_key

        for legacy_missing in ("algorithm", "encryption_context"):
            if legacy_missing not in kwargs:
                kwargs[legacy_missing] = None

        super(DecryptionMaterials, self).__init__(**kwargs)

        self.verification_key = verification_key
        attr.validate(self)

    @property
    def data_key(self):
        """Backwards-compatible shim."""
        return self.data_encryption_key

    @data_key.setter
    def data_key(self, value):
        # type: (DataKey) -> None
        """Backwards-compatible shim."""
        self.data_encryption_key = value
