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
    """
    def on_encrypt(self, encryption_materials):
        """Generates a data key and encrypts it using all wrapping keys the Keyring is associated with.

        :param encryption_materials: Contains signing key, encryption context and algorithm suite
                                    required to encrypt data key
        :type : aws_encryption_sdk.materials_managers.EncryptionMaterials
        :returns encryption_materials: Contains signing key, unencrypted data key, encrypted data keys,
                                    encryption context and algorithm suite required to encrypt data key
        :rtype : aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises AttributeError: if encryption materials not available
        """
        raise NotImplementedError("Keyring does not implement on_encrypt function")

    def on_decrypt(self, decryption_materials):
        """Tries to decrypt one of the keys in the list of encrypted data keys using wrapping keys
            the Keyring is associated with.

        :param decryption_materials: Contains verification key, list of encrypted data keys.
        :type : aws_encryption_sdk.materials_managers.DecryptionMaterials
        :returns decryption_materials: Contains verification key, list of encrypted data keys and decrypted data key.
        :rtype : aws_encryption_sdk.materials_managers.DecryptionMaterials
        :raises AttributeError: if decryption materials not available
        """
        raise NotImplementedError("Keyring does not implement on_decrypt function")
