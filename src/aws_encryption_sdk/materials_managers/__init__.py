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

from aws_encryption_sdk.exceptions import InvalidDataKeyError, InvalidKeyringTraceError, SignatureKeyError
from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag
from aws_encryption_sdk.internal.crypto.authentication import Signer, Verifier
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, KeyringTrace, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, FrozenSet, Iterable, Tuple, Union  # noqa pylint: disable=unused-import
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

    .. versionadded:: 1.5.0

    :param Algorithm algorithm: Algorithm to use for encrypting message
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param RawDataKey data_encryption_key: Plaintext data key to use for encrypting message
    :param keyring_trace: Any KeyRing trace entries
    :type keyring_trace: list of :class:`KeyringTrace`
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
    _keyring_trace = attr.ib(
        default=attr.Factory(list), validator=optional(deep_iterable(member_validator=instance_of(KeyringTrace)))
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

    def _validate_data_encryption_key(self, data_encryption_key, keyring_trace, required_flags):
        # type: (Union[DataKey, RawDataKey], KeyringTrace, Iterable[KeyringTraceFlag]) -> None
        """Validate that the provided data encryption key and keyring trace match for each other and the materials.

        :param RawDataKey data_encryption_key: Data encryption key
        :param KeyringTrace keyring_trace: Keyring trace corresponding to data_encryption_key
        :param required_flags: Iterable of required flags
        :type required_flags: iterable of :class:`KeyringTraceFlag`
        :raises AttributeError: if data encryption key is already set
        :raises InvalidKeyringTraceError: if keyring trace does not match decrypt action
        :raises InvalidKeyringTraceError: if keyring trace does not match data key provider
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        if self.data_encryption_key is not None:
            raise AttributeError("Data encryption key is already set.")

        for flag in required_flags:
            if flag not in keyring_trace.flags:
                raise InvalidKeyringTraceError("Keyring flags do not match action.")

        if keyring_trace.wrapping_key != data_encryption_key.key_provider:
            raise InvalidKeyringTraceError("Keyring trace does not match data key provider.")

        if len(data_encryption_key.data_key) != self.algorithm.kdf_input_len:
            raise InvalidDataKeyError(
                "Invalid data key length {actual} must be {expected}.".format(
                    actual=len(data_encryption_key.data_key), expected=self.algorithm.kdf_input_len
                )
            )

    def _add_data_encryption_key(self, data_encryption_key, keyring_trace, required_flags):
        # type: (Union[DataKey, RawDataKey], KeyringTrace, Iterable[KeyringTraceFlag]) -> None
        """Add a plaintext data encryption key.

        :param RawDataKey data_encryption_key: Data encryption key
        :param KeyringTrace keyring_trace: Trace of actions that a keyring performed
          while getting this data encryption key
        :param required_flags: Iterable of required flags
        :type required_flags: iterable of :class:`KeyringTraceFlag`
        :raises AttributeError: if data encryption key is already set
        :raises InvalidKeyringTraceError: if keyring trace does not match required actions
        :raises InvalidKeyringTraceError: if keyring trace does not match data key provider
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        self._validate_data_encryption_key(
            data_encryption_key=data_encryption_key, keyring_trace=keyring_trace, required_flags=required_flags
        )

        data_key = _data_key_to_raw_data_key(data_key=data_encryption_key)

        super(CryptographicMaterials, self).__setattr__("data_encryption_key", data_key)
        self._keyring_trace.append(keyring_trace)

    @property
    def keyring_trace(self):
        # type: () -> Tuple[KeyringTrace]
        """Return a read-only version of the keyring trace.

        :rtype: tuple
        """
        return tuple(self._keyring_trace)


@attr.s(hash=False, init=False)
class EncryptionMaterials(CryptographicMaterials):
    """Encryption materials returned by a crypto material manager's `get_encryption_materials` method.

    .. versionadded:: 1.3.0

    .. versionadded:: 1.5.0

        The **keyring_trace** parameter.

    .. versionadded:: 1.5.0

        Most parameters are now optional.

    :param Algorithm algorithm: Algorithm to use for encrypting message
    :param RawDataKey data_encryption_key: Plaintext data key to use for encrypting message (optional)
    :param encrypted_data_keys: List of encrypted data keys (optional)
    :type encrypted_data_keys: list of :class:`EncryptedDataKey`
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param bytes signing_key: Encoded signing key (optional)
    :param keyring_trace: Any KeyRing trace entries (optional)
    :type keyring_trace: list of :class:`KeyringTrace`
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

        if data_encryption_key is None and encrypted_data_keys is not None:
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

    @property
    def encrypted_data_keys(self):
        # type: () -> FrozenSet[EncryptedDataKey]
        """Return a read-only version of the encrypted data keys.

        :rtype: frozenset
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

    def add_data_encryption_key(self, data_encryption_key, keyring_trace):
        # type: (Union[DataKey, RawDataKey], KeyringTrace) -> None
        """Add a plaintext data encryption key.

        .. versionadded:: 1.5.0

        :param RawDataKey data_encryption_key: Data encryption key
        :param KeyringTrace keyring_trace: Trace of actions that a keyring performed
          while getting this data encryption key
        :raises AttributeError: if data encryption key is already set
        :raises InvalidKeyringTraceError: if keyring trace does not match generate action
        :raises InvalidKeyringTraceError: if keyring trace does not match data key provider
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        self._add_data_encryption_key(
            data_encryption_key=data_encryption_key,
            keyring_trace=keyring_trace,
            required_flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
        )

    def add_encrypted_data_key(self, encrypted_data_key, keyring_trace):
        # type: (EncryptedDataKey, KeyringTrace) -> None
        """Add an encrypted data key with corresponding keyring trace.

        .. versionadded:: 1.5.0

        :param EncryptedDataKey encrypted_data_key: Encrypted data key to add
        :param KeyringTrace keyring_trace: Trace of actions that a keyring performed
          while getting this encrypted data key
        :raises AttributeError: if data encryption key is not set
        :raises InvalidKeyringTraceError: if keyring trace does not match generate action
        :raises InvalidKeyringTraceError: if keyring trace does not match data key encryptor
        """
        if self.data_encryption_key is None:
            raise AttributeError("Data encryption key is not set.")

        if KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY not in keyring_trace.flags:
            raise InvalidKeyringTraceError("Keyring flags do not match action.")

        if keyring_trace.wrapping_key != encrypted_data_key.key_provider:
            raise InvalidKeyringTraceError("Keyring trace does not match data key encryptor.")

        self._encrypted_data_keys.append(encrypted_data_key)
        self._keyring_trace.append(keyring_trace)

    def add_signing_key(self, signing_key):
        # type: (bytes) -> None
        """Add a signing key.

        .. versionadded:: 1.5.0

        :param bytes signing_key: Signing key
        :raises AttributeError: if signing key is already set
        :raises SignatureKeyError: if algorithm suite does not support signing keys
        """
        if self.signing_key is not None:
            raise AttributeError("Signing key is already set.")

        if self.algorithm.signing_algorithm_info is None:
            raise SignatureKeyError("Algorithm suite does not support signing keys.")

        # Verify that the signing key matches the algorithm
        Signer.from_key_bytes(algorithm=self.algorithm, key_bytes=signing_key)

        self._setattr("signing_key", signing_key)


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

    .. versionadded:: 1.5.0

        The **algorithm**, **data_encryption_key**, **encryption_context**, and **keyring_trace** parameters.

    .. versionadded:: 1.5.0

        All parameters are now optional.

    :param Algorithm algorithm: Algorithm to use for encrypting message (optional)
    :param RawDataKey data_encryption_key: Plaintext data key to use for encrypting message (optional)
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys` (optional)
    :param bytes verification_key: Raw signature verification key (optional)
    :param keyring_trace: Any KeyRing trace entries (optional)
    :type keyring_trace: list of :class:`KeyringTrace`
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

    def add_data_encryption_key(self, data_encryption_key, keyring_trace):
        # type: (Union[DataKey, RawDataKey], KeyringTrace) -> None
        """Add a plaintext data encryption key.

        .. versionadded:: 1.5.0

        :param RawDataKey data_encryption_key: Data encryption key
        :param KeyringTrace keyring_trace: Trace of actions that a keyring performed
          while getting this data encryption key
        :raises AttributeError: if data encryption key is already set
        :raises InvalidKeyringTraceError: if keyring trace does not match decrypt action
        :raises InvalidKeyringTraceError: if keyring trace does not match data key provider
        :raises InvalidDataKeyError: if data key length does not match algorithm suite
        """
        if self.algorithm is None:
            raise AttributeError("Algorithm is not set")

        self._add_data_encryption_key(
            data_encryption_key=data_encryption_key,
            keyring_trace=keyring_trace,
            required_flags={KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY},
        )

    def add_verification_key(self, verification_key):
        # type: (bytes) -> None
        """Add a verification key.

        .. versionadded:: 1.5.0

        :param bytes verification_key: Verification key
        """
        if self.verification_key is not None:
            raise AttributeError("Verification key is already set.")

        if self.algorithm.signing_algorithm_info is None:
            raise SignatureKeyError("Algorithm suite does not support signing keys.")

        # Verify that the verification key matches the algorithm
        Verifier.from_key_bytes(algorithm=self.algorithm, key_bytes=verification_key)

        self._setattr("verification_key", verification_key)
