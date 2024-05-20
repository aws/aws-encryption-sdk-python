# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Master key that generates deterministic data keys and decrypts a pre-defined
encrypted data key value to that deterministic data keys.
"""
from typing import Dict, NoReturn, Text

from aws_encryption_sdk.exceptions import DecryptKeyError
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey


class CountingMasterKeyConfig(MasterKeyConfig):
    # pylint: disable=too-few-public-methods
    """Passthrough master key configuration to set the key id to "test_counting_prov_info"."""

    provider_id = "test_counting"

    def __init__(self) -> None:
        """Set the key id to "test_counting_prov_info"."""
        super().__init__(key_id=b"test_counting_prov_info")


class CountingMasterKey(MasterKey):
    r"""Master key that generates deterministic data keys and decrypts a pre-defined
    encrypted data key value to that deterministic data keys.

    Generated/decrypted data keys are of the form: ``\01\02\03\04...`` counting
    bytes up from one to the data key length required for a given algorithm suite.

    .. warning::

        This master key is NOT secure and should never be used for anything other than testing.

    """

    provider_id = "test_counting"
    _config_class = CountingMasterKeyConfig
    _encrypted_data_key = b"\x40\x41\x42\x43\x44"

    def _generate_data_key(self, algorithm: AlgorithmSuite, encryption_context: Dict[Text, Text]) -> DataKey:
        """Perform the provider-specific data key generation task.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """
        data_key = b"".join([chr(i).encode("utf-8") for i in range(1, algorithm.data_key_len + 1)])
        return DataKey(key_provider=self.key_provider, data_key=data_key, encrypted_data_key=self._encrypted_data_key)

    def _encrypt_data_key(
        self, data_key: DataKey, algorithm: AlgorithmSuite, encryption_context: Dict[Text, Text]
    ) -> NoReturn:
        """Encrypt a data key and return the ciphertext.

        :param data_key: Unencrypted data key
        :type data_key: :class:`aws_encryption_sdk.structures.RawDataKey`
            or :class:`aws_encryption_sdk.structures.DataKey`
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :raises NotImplementedError: when called
        """
        raise NotImplementedError("CountingMasterKey does not support encrypt_data_key")

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
        :raises DecryptKeyError: if Master Key is unable to decrypt data key
        """
        if encrypted_data_key.encrypted_data_key != self._encrypted_data_key:
            raise DecryptKeyError(
                'Master Key "{provider}" unable to decrypt data key'.format(provider=self.key_provider)
            )

        return self._generate_data_key(algorithm, encryption_context)
