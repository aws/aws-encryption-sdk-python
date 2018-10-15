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
"""Keyring that provides a translation layer between master key providers and keyrings.

.. versionadded:: 1.4.0
"""
import attr

from aws_encryption_sdk.exceptions import MasterKeyProviderError
from aws_encryption_sdk.internal.utils import prepare_data_keys
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.keyrings import Keyring
from aws_encryption_sdk.structures import DataKeyMaterials, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


@attr.s
class MasterKeyKeyring(Keyring):
    """Keyring that provides a translation layer between master key providers and keyrings.

    .. versionadded:: 1.4.0

    :param MasterKeyProvider master_key_provider: Master key provider to use
    """

    master_key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyProvider))
    _plaintext_rostream = None
    _plaintext_length = None

    def with_plaintext(self, plaintext_rostream, plaintext_length):
        # type: (Optional[ROStream], Optional[int]) -> MasterKeyKeyring
        """Build a new :class:`MasterKeyKeyring` with the provided plaintext information.

        :param ROStream plaintext_rostream: Stream that provides read-only access to plaintext data
        :param int plaintext_length: Length of plaintext data
        :return: Master key keyring with plaintext information
        :rtype: MasterKeyKeyring
        """
        new_keyring = MasterKeyKeyring(master_key_provider=self.master_key_provider)
        new_keyring._plaintext_rostream = plaintext_rostream
        new_keyring._plaintext_length = plaintext_length
        return new_keyring

    def _on_encrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on encrypt.

        :param DataKeyMaterials data_key_materials: Data key materials to start with
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """

        primary_master_key, master_keys = self.master_key_provider.master_keys_for_encryption(
            encryption_context=data_key_materials.encryption_context,
            # TODO: figure out how to pass through plaintext data...
            plaintext_rostream=self._plaintext_rostream,
            plaintext_length=self._plaintext_length,
        )

        if not master_keys:
            raise MasterKeyProviderError("No Master Keys available from Master Key Provider")

        if primary_master_key not in master_keys:
            raise MasterKeyProviderError("Primary Master Key not in provided Master Keys")

        data_encryption_key, encrypted_data_keys = prepare_data_keys(
            primary_master_key=primary_master_key,
            master_keys=master_keys,
            algorithm=data_key_materials.algorithm_suite,
            encryption_context=data_key_materials.encryption_context,
        )

        return DataKeyMaterials(
            algorithm_suite=data_key_materials.algorithm_suite,
            encryption_context=data_key_materials.encryption_context,
            plaintext_data_key=RawDataKey(
                key_provider=data_encryption_key.key_provider, data_key=data_encryption_key.data_key
            ),
            encrypted_data_keys=set(encrypted_data_keys),
        )

    def _on_decrypt(self, data_key_materials):
        # type: (DataKeyMaterials) -> DataKeyMaterials
        """Complete a data key materials for use on decrypt.

        :param DataKeyMaterials data_key_materials:
        :return: Data key materials with any applicable materials added
        :rtype: DataKeyMaterials
        """
        plaintext_data_key = self.master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=data_key_materials.encrypted_data_keys,
            algorithm=data_key_materials.algorithm_suite,
            encryption_context=data_key_materials.encryption_context,
        )

        return DataKeyMaterials(
            algorithm_suite=data_key_materials.algorithm_suite,
            encryption_context=data_key_materials.encryption_context,
            plaintext_data_key=RawDataKey(
                key_provider=plaintext_data_key.key_provider, data_key=plaintext_data_key.data_key
            ),
            encrypted_data_keys=set(data_key_materials.encrypted_data_keys),
        )
