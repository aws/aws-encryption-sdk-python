# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Resources required for Multi Keyrings."""
import itertools

import attr
from attr.validators import deep_iterable, instance_of, optional

from aws_encryption_sdk.exceptions import EncryptKeyError, GenerateKeyError
from aws_encryption_sdk.keyrings.base import Keyring

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

__all__ = ("MultiKeyring",)


@attr.s
class MultiKeyring(Keyring):
    """Public class for Multi Keyring.

    .. versionadded:: 1.5.0

    :param Keyring generator: Generator keyring used to generate data encryption key (optional)
    :param List[Keyring] children: List of keyrings used to encrypt the data encryption key (optional)
    :raises EncryptKeyError: if encryption of data key fails for any reason
    """

    generator = attr.ib(default=None, validator=optional(instance_of(Keyring)))
    children = attr.ib(
        default=attr.Factory(tuple), validator=optional(deep_iterable(member_validator=instance_of(Keyring)))
    )

    def __attrs_post_init__(self):
        # type: () -> None
        """Prepares initial values not handled by attrs."""
        neither_generator_nor_children = self.generator is None and not self.children
        if neither_generator_nor_children:
            raise TypeError("At least one of generator or children must be provided")

        _generator = (self.generator,) if self.generator is not None else ()
        self._decryption_keyrings = list(itertools.chain(_generator, self.children))

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key using generator keyring
        and encrypt it using any available wrapping key in any child keyring.

        :param EncryptionMaterials encryption_materials: Encryption materials for keyring to modify.
        :returns: Optionally modified encryption materials.
        :rtype: EncryptionMaterials
        :raises EncryptKeyError: if unable to encrypt data key.
        """
        # Check if generator keyring is not provided and data key is not generated
        if self.generator is None and encryption_materials.data_encryption_key is None:
            raise EncryptKeyError(
                "Generator keyring not provided "
                "and encryption materials do not already contain a plaintext data key."
            )

        # Call on_encrypt on the generator keyring if it is provided
        if self.generator is not None:

            encryption_materials = self.generator.on_encrypt(encryption_materials=encryption_materials)

        # Check if data key is generated
        if encryption_materials.data_encryption_key is None:
            raise GenerateKeyError("Unable to generate data encryption key.")

        # Call on_encrypt on all other keyrings
        for keyring in self.children:
            encryption_materials = keyring.on_encrypt(encryption_materials=encryption_materials)

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param DecryptionMaterials decryption_materials: Decryption materials for keyring to modify.
        :param List[EncryptedDataKey] encrypted_data_keys: List of encrypted data keys.
        :returns: Optionally modified decryption materials.
        :rtype: DecryptionMaterials
        """
        # Call on_decrypt on all keyrings till decryption is successful
        for keyring in self._decryption_keyrings:
            if decryption_materials.data_encryption_key is not None:
                return decryption_materials
            decryption_materials = keyring.on_decrypt(
                decryption_materials=decryption_materials, encrypted_data_keys=encrypted_data_keys
            )
        return decryption_materials
