"""Master key that provides null data keys."""
from aws_encryption_sdk.identifiers import AlgorithmSuite  # noqa pylint: disable=unused-import
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig
from aws_encryption_sdk.structures import EncryptedDataKey  # noqa pylint: disable=unused-import
from aws_encryption_sdk.structures import DataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Text, NoReturn  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


class NullMasterKeyConfig(MasterKeyConfig):
    # pylint: disable=too-few-public-methods
    """"""

    provider_id = "null"

    def __init__(self):
        # type: () -> None
        """"""
        super(NullMasterKeyConfig, self).__init__(key_id=b"null")


class NullMasterKey(MasterKey):
    """"""

    provider_id = "null"
    _allowed_provider_ids = (provider_id, "zero")
    _config_class = NullMasterKeyConfig

    def owns_data_key(self, data_key):
        # type: (DataKey) -> bool
        """Determine whether the data key is owned by a ``null`` or ``zero`` provider.

        :param data_key: Data key to evaluate
        :type data_key: :class:`aws_encryption_sdk.structures.DataKey`,
            :class:`aws_encryption_sdk.structures.RawDataKey`,
            or :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Boolean statement of ownership
        :rtype: bool
        """
        return data_key.key_provider.provider_id in self._allowed_provider_ids

    def _generate_data_key(self, algorithm, encryption_context):
        # type: (AlgorithmSuite, Dict[Text, Text]) -> NoReturn
        """NullMasterKey does not support generate_data_key

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :raises NotImplementedError: when called
        """
        raise NotImplementedError("NullMasterKey does not support generate_data_key")

    def _encrypt_data_key(self, data_key, algorithm, encryption_context):
        # type: (DataKey, AlgorithmSuite,  Dict[Text, Text]) -> NoReturn
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
        """
        data_key = b"\x00" * algorithm.data_key_len
        return DataKey(
            key_provider=self.key_provider, data_key=data_key, encrypted_data_key=encrypted_data_key.encrypted_data_key
        )
