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
"""Master key that provides null data keys."""
from typing import Dict, NoReturn, Text

from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig
from aws_encryption_sdk.structures import EncryptedDataKey
from aws_encryption_sdk.structures import DataKey


class NullMasterKeyConfig(MasterKeyConfig):
    # pylint: disable=too-few-public-methods
    """Passthrough master key configuration to set the key id to "null"."""

    provider_id = "null"

    def __init__(self) -> None:
        """Set the key id to "null"."""
        super(NullMasterKeyConfig, self).__init__(key_id=b"null")


class NullMasterKey(MasterKey):
    """Master key that generates null data keys and decrypts any data key with provider id
    "null" or "zero" as a null data key."""

    provider_id = "null"
    _allowed_provider_ids = (provider_id, "zero")
    _config_class = NullMasterKeyConfig

    def owns_data_key(self, data_key: DataKey) -> bool:
        """Determine whether the data key is owned by a ``null`` or ``zero`` provider.

        :param data_key: Data key to evaluate
        :type data_key: :class:`aws_encryption_sdk.structures.DataKey`,
            :class:`aws_encryption_sdk.structures.RawDataKey`,
            or :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Boolean statement of ownership
        :rtype: bool
        """
        return data_key.key_provider.provider_id in self._allowed_provider_ids

    @staticmethod
    def _null_plaintext_data_key(algorithm: AlgorithmSuite) -> bytes:
        """Build the null data key of the correct length for the requested algorithm suite.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :returns: Null data key
        :rtype: bytes
        """
        return b"\x00" * algorithm.data_key_len

    def _generate_data_key(self, algorithm: AlgorithmSuite, encryption_context: Dict[Text, Text]) -> DataKey:
        """NullMasterKey does not support generate_data_key

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :raises NotImplementedError: when called
        """
        return DataKey(
            key_provider=self.key_provider, data_key=self._null_plaintext_data_key(algorithm), encrypted_data_key=b""
        )

    def _encrypt_data_key(
        self, data_key: DataKey, algorithm: AlgorithmSuite, encryption_context: Dict[Text, Text]
    ) -> NoReturn:
        """NullMasterKey does not support encrypt_data_key

        :param data_key: Unencrypted data key
        :type data_key: :class:`aws_encryption_sdk.structures.RawDataKey`
            or :class:`aws_encryption_sdk.structures.DataKey`
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :raises NotImplementedError: when called
        """
        raise NotImplementedError("NullMasterKey does not support encrypt_data_key")

    def _decrypt_data_key(
        self, encrypted_data_key: EncryptedDataKey, algorithm: AlgorithmSuite, encryption_context: Dict[Text, Text]
    ) -> DataKey:
        """Decrypt an encrypted data key and return the plaintext.

        :param data_key: Encrypted data key
        :type data_key: aws_encryption_sdk.structures.EncryptedDataKey
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Data key containing decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """
        return DataKey(
            key_provider=self.key_provider,
            data_key=self._null_plaintext_data_key(algorithm),
            encrypted_data_key=encrypted_data_key.encrypted_data_key,
        )
