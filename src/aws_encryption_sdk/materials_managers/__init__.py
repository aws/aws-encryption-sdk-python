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
import copy

import attr
import six
from attr.validators import deep_iterable, deep_mapping, instance_of, optional

from aws_encryption_sdk.exceptions import InvalidDataKeyError, SignatureKeyError
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.crypto.authentication import Signer, Verifier
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Iterable, Tuple, Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


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

    encryption_context = attr.ib(
        validator=deep_mapping(
            key_validator=instance_of(six.string_types), value_validator=instance_of(six.string_types)
        )
    )
    frame_length = attr.ib(validator=instance_of(six.integer_types))
    plaintext_rostream = attr.ib(default=None, validator=optional(instance_of(ROStream)))
    algorithm = attr.ib(default=None, validator=optional(instance_of(Algorithm)))
    plaintext_length = attr.ib(default=None, validator=optional(instance_of(six.integer_types)))


def _data_key_to_raw_data_key(data_key):
    # type: (Union[DataKey, RawDataKey, None]) -> Union[RawDataKey, None]
    """Convert a :class:`DataKey` into a :class:`RawDataKey`."""
    if isinstance(data_key, RawDataKey) or data_key is None:
        return data_key

    return RawDataKey.from_data_key(data_key=data_key)


@attr.s
class CryptographicMaterials(object):
    """Cryptographic materials core.

    .. versionadded:: 2.0.0

    :param Algorithm algorithm: Algorithm to use for encrypting message
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param RawDataKey data_encryption_key: Plaintext data key to use for encrypting message
    """

    algorithm = attr.ib(validator=optional(instance_of(Algorithm)))
    encryption_context = attr.ib(
        validator=optional(
            deep_mapping(key_validator=instance_of(six.string_types), value_validator=instance_of(six.string_types))
        )
    )
    data_encryption_key = attr.ib(
        default=None, validator=optional(instance_of(RawDataKey)), converter=_data_key_to_raw_data_key
    )
    _initialized = False

    def __attrs_post_init__(self):
        """Freeze attributes after initialization."""
        self._initialized = True

    def __setattr__(self, key, value):
        # type: (str, Any) -> None
        """Do not allow attributes to be changed once an instance is initialized."""
        if self._initialized:
            raise AttributeError("can't set attribute")

        self._setattr(key, value)

    def _setattr(self, key, value):
        # type: (str, Any) -> None
        """Special __setattr__ to avoid having to perform multi-level super calls."""
        super(CryptographicMaterials, self).__setattr__(key, value)

    def _validate_data_encryption_key(self, data_encryption_key):
        # type: (Union[DataKey, RawDataKey]) -> None
        """Validate that the provided data encryption key matches the materials.

        .. versionadded:: 2.0.0

        :param RawDataKey data_encryption_key: Data encryption key
        :raises AttributeError: if data encryption key is already set
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        if self.data_encryption_key is not None:
            raise AttributeError("Data encryption key is already set.")

        if len(data_encryption_key.data_key) != self.algorithm.kdf_input_len:
            raise InvalidDataKeyError(
                "Invalid data key length {actual} must be {expected}.".format(
                    actual=len(data_encryption_key.data_key), expected=self.algorithm.kdf_input_len
                )
            )

    def _with_data_encryption_key(self, data_encryption_key):
        # type: (Union[DataKey, RawDataKey]) -> CryptographicMaterials
        """Get new cryptographic materials that include this data encryption key.

        .. versionadded:: 2.0.0

        :param RawDataKey data_encryption_key: Data encryption key
        :raises AttributeError: if data encryption key is already set
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        self._validate_data_encryption_key(data_encryption_key=data_encryption_key)

        new_materials = copy.copy(self)

        data_key = _data_key_to_raw_data_key(data_key=data_encryption_key)
        new_materials._setattr(  # simplify access to copies pylint: disable=protected-access
            "data_encryption_key", data_key
        )

        return new_materials


@attr.s(hash=False, init=False)
class EncryptionMaterials(CryptographicMaterials):
    """Encryption materials returned by a crypto material manager's `get_encryption_materials` method.

    .. versionadded:: 1.3.0

    .. versionadded:: 2.0.0

        Most parameters are now optional.

    :param Algorithm algorithm: Algorithm to use for encrypting message
    :param RawDataKey data_encryption_key: Plaintext data key to use for encrypting message (optional)
    :param encrypted_data_keys: List of encrypted data keys (optional)
    :type encrypted_data_keys: list of :class:`EncryptedDataKey`
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param bytes signing_key: Encoded signing key (optional)
    """

    _encrypted_data_keys = attr.ib(
        default=attr.Factory(list), validator=optional(deep_iterable(member_validator=instance_of(EncryptedDataKey)))
    )
    signing_key = attr.ib(default=None, repr=False, validator=optional(instance_of(bytes)))

    def __init__(
        self,
        algorithm=None,
        data_encryption_key=None,
        encrypted_data_keys=None,
        encryption_context=None,
        signing_key=None,
        **kwargs
    ):  # noqa we define this in the class docstring
        if algorithm is None:
            raise TypeError("algorithm must not be None")

        if encryption_context is None:
            raise TypeError("encryption_context must not be None")

        if data_encryption_key is None and encrypted_data_keys:
            # If data_encryption_key is not set, encrypted_data_keys MUST be either None or empty
            raise TypeError("encrypted_data_keys cannot be provided without data_encryption_key")

        if encrypted_data_keys is None:
            encrypted_data_keys = []

        super(EncryptionMaterials, self).__init__(
            algorithm=algorithm,
            encryption_context=encryption_context,
            data_encryption_key=data_encryption_key,
            **kwargs
        )
        self._setattr("signing_key", signing_key)
        self._setattr("_encrypted_data_keys", encrypted_data_keys)
        attr.validate(self)

    def __copy__(self):
        # type: () -> EncryptionMaterials
        """Do a shallow copy of this instance."""
        return EncryptionMaterials(
            algorithm=self.algorithm,
            data_encryption_key=self.data_encryption_key,
            encrypted_data_keys=copy.copy(self._encrypted_data_keys),
            encryption_context=self.encryption_context.copy(),
            signing_key=self.signing_key,
        )

    @property
    def encrypted_data_keys(self):
        # type: () -> Tuple[EncryptedDataKey]
        """Return a read-only version of the encrypted data keys.

        :rtype: Tuple[EncryptedDataKey]
        """
        return tuple(self._encrypted_data_keys)

    @property
    def is_complete(self):
        # type: () -> bool
        """Determine whether these materials are sufficiently complete for use as encryption materials.

        :rtype: bool
        """
        if self.data_encryption_key is None:
            return False

        if not self.encrypted_data_keys:
            return False

        if self.algorithm.signing_algorithm_info is not None and self.signing_key is None:
            return False

        return True

    def with_data_encryption_key(self, data_encryption_key):
        # type: (Union[DataKey, RawDataKey]) -> EncryptionMaterials
        """Get new encryption materials that also include this data encryption key.

        .. versionadded:: 2.0.0

        :param RawDataKey data_encryption_key: Data encryption key
        :rtype: EncryptionMaterials
        :raises AttributeError: if data encryption key is already set
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        return self._with_data_encryption_key(data_encryption_key=data_encryption_key,)

    def with_encrypted_data_key(self, encrypted_data_key):
        # type: (EncryptedDataKey) -> EncryptionMaterials
        """Get new encryption materials that also include this encrypted data key.

        .. versionadded:: 2.0.0

        :param EncryptedDataKey encrypted_data_key: Encrypted data key to add
        :rtype: EncryptionMaterials
        :raises AttributeError: if data encryption key is not set
        """
        if self.data_encryption_key is None:
            raise AttributeError("Data encryption key is not set.")

        new_materials = copy.copy(self)

        new_materials._encrypted_data_keys.append(  # simplify access to copies pylint: disable=protected-access
            encrypted_data_key
        )
        return new_materials

    def with_signing_key(self, signing_key):
        # type: (bytes) -> EncryptionMaterials
        """Get new encryption materials that also include this signing key.

        .. versionadded:: 2.0.0

        :param bytes signing_key: Signing key
        :rtype: EncryptionMaterials
        :raises AttributeError: if signing key is already set
        :raises SignatureKeyError: if algorithm suite does not support signing keys
        """
        if self.signing_key is not None:
            raise AttributeError("Signing key is already set.")

        if self.algorithm.signing_algorithm_info is None:
            raise SignatureKeyError("Algorithm suite does not support signing keys.")

        new_materials = copy.copy(self)

        # Verify that the signing key matches the algorithm
        Signer.from_key_bytes(algorithm=new_materials.algorithm, key_bytes=signing_key)

        new_materials._setattr("signing_key", signing_key)  # simplify access to copies pylint: disable=protected-access

        return new_materials


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

    algorithm = attr.ib(validator=instance_of(Algorithm))
    encrypted_data_keys = attr.ib(validator=deep_iterable(member_validator=instance_of(EncryptedDataKey)))
    encryption_context = attr.ib(
        validator=deep_mapping(
            key_validator=instance_of(six.string_types), value_validator=instance_of(six.string_types)
        )
    )


_DEFAULT_SENTINEL = object()


@attr.s(hash=False, init=False)
class DecryptionMaterials(CryptographicMaterials):
    """Decryption materials returned by a crypto material manager's `decrypt_materials` method.

    .. versionadded:: 1.3.0

    .. versionadded:: 2.0.0

        The **algorithm**, **data_encryption_key**, and **encryption_context** parameters.

    .. versionadded:: 2.0.0

        All parameters are now optional.

    :param Algorithm algorithm: Algorithm to use for encrypting message (optional)
    :param RawDataKey data_encryption_key: Plaintext data key to use for encrypting message (optional)
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys` (optional)
    :param bytes verification_key: Raw signature verification key (optional)
    """

    verification_key = attr.ib(default=None, repr=False, validator=optional(instance_of(bytes)))

    def __init__(
        self, data_key=_DEFAULT_SENTINEL, verification_key=None, **kwargs
    ):  # noqa we define this in the class docstring

        legacy_data_key_set = data_key is not _DEFAULT_SENTINEL
        data_encryption_key_set = "data_encryption_key" in kwargs

        if legacy_data_key_set and data_encryption_key_set:
            raise TypeError("Either data_key or data_encryption_key can be used but not both")

        if legacy_data_key_set and not data_encryption_key_set:
            kwargs["data_encryption_key"] = data_key

        for legacy_missing in ("algorithm", "encryption_context"):
            if legacy_missing not in kwargs:
                kwargs[legacy_missing] = None

        super(DecryptionMaterials, self).__init__(**kwargs)

        self._setattr("verification_key", verification_key)
        attr.validate(self)

    def __copy__(self):
        # type: () -> DecryptionMaterials
        """Do a shallow copy of this instance."""
        return DecryptionMaterials(
            algorithm=self.algorithm,
            data_encryption_key=self.data_encryption_key,
            encryption_context=copy.copy(self.encryption_context),
            verification_key=self.verification_key,
        )

    @property
    def is_complete(self):
        # type: () -> bool
        """Determine whether these materials are sufficiently complete for use as decryption materials.

        :rtype: bool
        """
        if None in (self.algorithm, self.encryption_context):
            return False

        if self.data_encryption_key is None:
            return False

        if self.algorithm.signing_algorithm_info is not None and self.verification_key is None:
            return False

        return True

    @property
    def data_key(self):
        # type: () -> RawDataKey
        """Backwards-compatible shim for access to data key."""
        return self.data_encryption_key

    def with_data_encryption_key(self, data_encryption_key):
        # type: (Union[DataKey, RawDataKey]) -> DecryptionMaterials
        """Get new decryption materials that also include this data encryption key.

        .. versionadded:: 2.0.0

        :param RawDataKey data_encryption_key: Data encryption key
        :rtype: DecryptionMaterials
        :raises AttributeError: if data encryption key is already set
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        if self.algorithm is None:
            raise AttributeError("Algorithm is not set")

        return self._with_data_encryption_key(data_encryption_key=data_encryption_key)

    def with_verification_key(self, verification_key):
        # type: (bytes) -> DecryptionMaterials
        """Get new decryption materials that also include this verification key.

        .. versionadded:: 2.0.0

        :param bytes verification_key: Verification key
        :rtype: DecryptionMaterials
        """
        if self.verification_key is not None:
            raise AttributeError("Verification key is already set.")

        if self.algorithm.signing_algorithm_info is None:
            raise SignatureKeyError("Algorithm suite does not support signing keys.")

        new_materials = copy.copy(self)

        # Verify that the verification key matches the algorithm
        Verifier.from_key_bytes(algorithm=new_materials.algorithm, key_bytes=verification_key)

        new_materials._setattr(  # simplify access to copies pylint: disable=protected-access
            "verification_key", verification_key
        )

        return new_materials
