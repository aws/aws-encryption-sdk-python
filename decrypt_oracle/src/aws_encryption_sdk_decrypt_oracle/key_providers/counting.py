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
"""
Master key that generates deterministic data keys and decrypts a pre-defined
encrypted data key value to that deterministic data keys.
"""
from aws_encryption_sdk.exceptions import DecryptKeyError
from aws_encryption_sdk.identifiers import AlgorithmSuite  # noqa pylint: disable=unused-import
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig
from aws_encryption_sdk.structures import EncryptedDataKey  # noqa pylint: disable=unused-import
from aws_encryption_sdk.structures import DataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Text, NoReturn  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


class CountingMasterKeyConfig(MasterKeyConfig):
    # pylint: disable=too-few-public-methods
    """Passthrough master key configuration to set the key id to "test_counting_prov_info"."""

    provider_id = "test_counting"

    def __init__(self):
        # type: () -> None
        """Set the key id to "test_counting_prov_info"."""
        super(CountingMasterKeyConfig, self).__init__(key_id=b"test_counting_prov_info")


class CountingMasterKey(MasterKey):
    """Master key that generates deterministic data keys and decrypts a pre-defined
    encrypted data key value to that deterministic data keys.

    Generated/decrypted data keys are of the form: ``\01\02\03\04...`` counting
    bytes up from one to the data key length required for a given algorithm suite.
    """

    provider_id = "test_counting"
    _config_class = CountingMasterKeyConfig
    _encrypted_data_key = b"\x40\x41\x42\x43\x44"

    def _generate_data_key(self, algorithm, encryption_context):
        # type: (AlgorithmSuite, Dict[Text, Text]) -> DataKey
        """Perform the provider-specific data key generation task.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """
        data_key = b"".join([chr(i).encode("utf-8") for i in range(1, algorithm.data_key_len + 1)])
        return DataKey(key_provider=self.key_provider, data_key=data_key, encrypted_data_key=self._encrypted_data_key)

    def _encrypt_data_key(self, data_key, algorithm, encryption_context):
        # type: (DataKey, AlgorithmSuite,  Dict[Text, Text]) -> NoReturn
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

    def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        # type: (EncryptedDataKey, AlgorithmSuite, Dict[Text, Text]) -> DataKey
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
