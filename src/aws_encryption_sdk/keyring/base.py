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
"""Base class interface for Keyrings."""


class Keyring(object):
    """Parent interface for Keyring classes.

    .. versionadded:: 1.5.0
    """

    def on_encrypt(self, encryption_materials):
    # type: (EncryptionMaterials) -> EncryptionMaterials
        """Generate a data key if not present and encrypt it using any available wrapping key.

        :param encryption_materials: Contains signing key, encryption context and algorithm suite
                                    required to encrypt data key
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns: Encryption materials containing signing key, unencrypted data key, encrypted data keys,
                                    encryption context and algorithm suite required to encrypt data key
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises NotImplementedError: if method is not implemented
        """
        raise NotImplementedError("Keyring does not implement on_encrypt function")

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        """Attempt to decrypt the encrypted data keys.

        :param decryption_materials: May contain verification key, algorithm, encryption context and keyring trace.
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :param encrypted_data_keys: List of encrypted data keys.
        :type: Iterable of :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Decryption materials containing verification key, algorithm, data_encryption_key,
                    encryption context and keyring trace.
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :raises NotImplementedError: if method is not implemented
        """
        raise NotImplementedError("Keyring does not implement on_decrypt function")
