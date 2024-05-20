# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Contains data key helper functions."""
import logging
import struct

from cryptography.hazmat.backends import default_backend

_LOGGER = logging.getLogger(__name__)

# Used in SerializationVersion.V2 to calculate the derived key
KEY_LABEL = b"DERIVEKEY"

# Used in SerializationVersion.V2 to calculate the commitment key
COMMIT_LABEL = b"COMMITKEY"

# Used in SerializationVersion.V2 to calculate the commitment key
L_C = 32


def derive_data_encryption_key(source_key, algorithm, message_id):
    """Derives the data encryption key using the defined algorithm.

    :param bytes source_key: Raw source key
    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes message_id: Message ID
    :returns: Derived data encryption key
    :rtype: bytes
    """
    key = source_key
    if algorithm.kdf_type is not None:
        if algorithm.is_committing():
            key = algorithm.kdf_type(
                algorithm=algorithm.kdf_hash_type(),
                length=algorithm.data_key_len,
                salt=message_id,
                info=struct.pack(">H9s", algorithm.algorithm_id, KEY_LABEL),
                backend=default_backend(),
            ).derive(source_key)
        else:
            key = algorithm.kdf_type(
                algorithm=algorithm.kdf_hash_type(),
                length=algorithm.data_key_len,
                salt=None,
                info=struct.pack(">H16s", algorithm.algorithm_id, message_id),
                backend=default_backend(),
            ).derive(source_key)
    return key


def calculate_commitment_key(source_key, algorithm, message_id):
    """Calculates the commitment value.

    :param bytes source_key: Raw source key
    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes message_id: Message ID
    :returns: Derived data encryption key
    :rtype: bytes
    """
    key = algorithm.kdf_type(
        algorithm=algorithm.kdf_hash_type(),
        length=L_C,
        salt=message_id,
        info=struct.pack(">9s", COMMIT_LABEL),
        backend=default_backend(),
    ).derive(source_key)
    return key
