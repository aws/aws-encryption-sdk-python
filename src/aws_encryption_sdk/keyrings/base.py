# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Base class interface for Keyrings."""
from aws_encryption_sdk.materials_managers import (  # only used for mypy; pylint: disable=unused-import
    DecryptionMaterials,
    EncryptionMaterials,
)
from aws_encryption_sdk.structures import EncryptedDataKey  # only used for mypy; pylint: disable=unused-import

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("Keyring",)


class Keyring(object):
    """Parent interface for Keyring classes.

    .. versionadded:: 1.5.0
    """

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param EncryptionMaterials encryption_materials: Encryption materials for keyring to modify.
        :returns: Optionally modified encryption materials.
        :rtype: EncryptionMaterials
        :raises NotImplementedError: if method is not implemented
        """
        raise NotImplementedError("Keyring does not implement on_encrypt function")

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param DecryptionMaterials decryption_materials: Decryption materials for keyring to modify.
        :param List[EncryptedDataKey] encrypted_data_keys: List of encrypted data keys.
        :returns: Optionally modified decryption materials.
        :rtype: DecryptionMaterials
        :raises NotImplementedError: if method is not implemented
        """
        raise NotImplementedError("Keyring does not implement on_decrypt function")
