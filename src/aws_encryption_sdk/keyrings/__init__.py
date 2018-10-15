# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Interfaces and base class for keyrings.

.. versionadded:: 1.4.0
"""
from zope.interface import Interface, implementer

from aws_encryption_sdk.structures import DataKeyMaterials


class KeyringPublicInterface(Interface):
    """The public interface that all keyrings expose."""

    def on_encrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on encrypt.

        :param DataKeyMaterials data_key_materials: Data key materials to start with
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """

    def on_decrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on decrypt.

        :param DataKeyMaterials data_key_materials:
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """


class KeyringPrivateInterface(Interface):
    """The private interface that every ``Keyring`` child must implement.

    .. note::

        This is the interface that keyrings subclassing from :class:`Keyring`
        should be implementing.
    """

    def _on_encrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on encrypt.

        :param DataKeyMaterials data_key_materials: Data key materials to start with
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """

    def _on_decrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on decrypt.

        :param DataKeyMaterials data_key_materials:
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """


@implementer(KeyringPublicInterface)
@implementer(KeyringPrivateInterface)
class Keyring(object):
    """Parent class for all keyrings."""

    def on_encrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on encrypt.

        :param DataKeyMaterials data_key_materials: Data key materials to start with
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """
        if data_key_materials.plaintext_data_key is None and data_key_materials.encrypted_data_keys:
            raise Exception(
                "TODO: " "On encrypt, data key materials cannot contain encrypted data keys but no plaintext data key."
            )

        return self._on_encrypt(data_key_materials)

    def on_decrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on decrypt.

        :param DataKeyMaterials data_key_materials:
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """
        if data_key_materials.plaintext_data_key is not None:
            return data_key_materials

        if not data_key_materials.encrypted_data_keys:
            raise Exception("TODO: " "No encrypted data keys found.")

        return self._on_decrypt(data_key_materials)
