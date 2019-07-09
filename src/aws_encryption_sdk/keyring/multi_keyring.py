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
"""Resources required for Multi Keyrings."""
import attr

from aws_encryption_sdk.exceptions import EncryptKeyError
from aws_encryption_sdk.keyring.base import Keyring

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


@attr.s
class MultiKeyring(Keyring):
    """Public class for Multi Keyring.

    :param generator: Generator keyring used to generate data encryption key
    :type generator: Keyring
    :param list children: List of keyrings used to encrypt the data encryption key
    :raises EncryptKeyError: if encryption of data key fails for any reason
    """

    generator = attr.ib(validator=attr.validators.instance_of(Keyring))
    children = attr.ib(validator=attr.validators.instance_of(list))

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key using generator keyring
        and encrypt it using any available wrapping key in any child keyring.

        :param encryption_materials: Encryption materials for keyring to modify.
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Optionally modified encryption materials.
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises EncryptKeyError: if unable to encrypt data key.
        """
        # Check if generator keyring is provided
        if not self.generator:
            raise EncryptKeyError("Generator keyring not provided.")

        # Check if generator keyring is provided and data key is generated
        if self.generator and encryption_materials.data_encryption_key:
            raise EncryptKeyError("Data encryption key already exists.")

        # Call on_encrypt on the generator keyring
        encryption_materials = self.generator.on_encrypt(encryption_materials)

        # Check if data key is generated
        if not encryption_materials.data_encryption_key:
            raise EncryptKeyError("Unable to generate data encryption key.")

        # Call on_encrypt on all other keyrings
        for keyring in self.children:
            encryption_materials = keyring.on_encrypt(encryption_materials)

        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: Decryption materials for keyring to modify.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :param encrypted_data_keys: List of encrypted data keys.
        :type: List of `aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Optionally modified decryption materials.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        # Check if plaintext data key exists
        if decryption_materials.data_key:
            return decryption_materials

        # Call on_decrypt on all keyrings till decryption is successful
        for keyring in self.children:
            decryption_materials = keyring.on_decrypt(decryption_materials, encrypted_data_keys)
            if decryption_materials.data_key:
                return decryption_materials

        return decryption_materials
