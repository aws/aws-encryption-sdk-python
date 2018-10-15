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

from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.structures import DataKey, DataKeyMaterials, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Optional  # noqa pylint: disable=unused-import
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

    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    frame_length = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    plaintext_rostream = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(ROStream))
    )
    algorithm = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(Algorithm)))
    plaintext_length = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )

    def to_data_key_materials(self, override_algorithm_suite=None, override_encryption_context=None):
        # type: (Optional[Algorithm], Optional[Dict[str, str]]) -> DataKeyMaterials
        """Build :class:`DataKeyMaterials` from this request.
        If algorith suite and encryption context are provided, they are used instead of the values in this request.

        .. versionadded:: 1.4.0

        :param AlgorithmSuite override_algorithm_suite: Override value to use for algorithm suite
        :param dict[str, str] override_encryption_context: Override value to use for encryption context
        :return: Data key materials built from this request
        :rtype: DataKeyMaterials
        """
        algorithm = override_algorithm_suite if override_algorithm_suite is not None else self.algorithm
        encryption_context = (
            override_encryption_context if override_encryption_context is not None else self.encryption_context
        )
        return DataKeyMaterials(algorithm_suite=algorithm, encryption_context=encryption_context)


@attr.s(hash=False)
class EncryptionMaterials(object):
    """Encryption materials returned by a crypto material manager's `get_encryption_materials` method.

    .. versionadded:: 1.3.0

    :param algorithm: Algorithm to use for encrypting message
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param data_encryption_key: Plaintext data key to use for encrypting message
    :type data_encryption_key: :class`DataKey` or :class:`RawDataKey`
    :param encrypted_data_keys: List of encrypted data keys
    :type encrypted_data_keys: list of :class:`EncryptedDataKey`
    :param dict encryption_context: Encryption context tied to `encrypted_data_keys`
    :param bytes signing_key: Encoded signing key
    """

    algorithm = attr.ib(validator=attr.validators.instance_of(Algorithm))
    data_encryption_key = attr.ib(validator=attr.validators.instance_of((DataKey, RawDataKey)))
    encrypted_data_keys = attr.ib(validator=attr.validators.instance_of(set))
    encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    signing_key = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))

    @classmethod
    def from_data_key_materials(cls, data_key_materials, signing_key):
        # type: (DataKeyMaterials, bytes) -> EncryptionMaterials
        """Load :class:`EncryptionMaterials` from :class:`DataKeyMaterials` with the provided signing key.

        .. versionadded:: 1.4.0

        :param DataKeyMaterials data_key_materials: DataKeyMaterials
        :param bytes signing_key: Signing key to include in encryption materials
        :return: Loaded encryption materials
        :rtype: EncryptionMaterials
        """
        return EncryptionMaterials(
            algorithm=data_key_materials.algorithm_suite,
            data_encryption_key=data_key_materials.plaintext_data_key,
            encrypted_data_keys=set(data_key_materials.encrypted_data_keys),
            encryption_context=data_key_materials.encryption_context,
            signing_key=signing_key,
        )


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

    def to_data_key_materials(self):
        # type: () -> DataKeyMaterials
        """Build :class:`DataKeyMaterials` from this request.

        .. versionadded:: 1.4.0

        :return: Data key materials built from this request
        :rtype: DataKeyMaterials
        """
        return DataKeyMaterials(
            algorithm_suite=self.algorithm,
            encryption_context=self.encryption_context,
            encrypted_data_keys=self.encrypted_data_keys,
        )


@attr.s(hash=False)
class DecryptionMaterials(object):
    """Decryption materials returned by a crypto material manager's `decrypt_materials` method.

    .. versionadded:: 1.3.0

    :param data_key: Plaintext data key to use with message decryption
    :type data_key: DataKey or RawDataKey
    :param bytes verification_key: Raw signature verification key
    """

    data_key = attr.ib(validator=attr.validators.instance_of((DataKey, RawDataKey)))
    verification_key = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(bytes)))

    @classmethod
    def from_data_key_materials(cls, data_key_materials, verification_key):
        # type: (DataKeyMaterials, Optional[bytes]) -> DecryptionMaterials
        """Load :class:`DecryptionMaterials` from :class:`DataKeyMaterials` with the provided verification key.

        .. versionadded:: 1.4.0

        :param DataKeyMaterials data_key_materials: Data key materials from which to load decryption materials
        :param bytes verification_key: Verification key to use
        :return: Loaded decryption materials
        :rtype: DecryptionMaterials
        """
        return DecryptionMaterials(data_key=data_key_materials.plaintext_data_key, verification_key=verification_key)
