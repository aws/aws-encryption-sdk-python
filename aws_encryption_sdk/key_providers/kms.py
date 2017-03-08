"""Master Key Providers for use with AWS KMS"""
import logging

import attr
import boto3
import botocore.client
from botocore.exceptions import ClientError
import botocore.session

from aws_encryption_sdk.exceptions import GenerateKeyError, DecryptKeyError, EncryptKeyError, UnknownRegionError
from aws_encryption_sdk.identifiers import __version__
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.key_providers.base import (
    MasterKeyProvider, MasterKeyProviderConfig, MasterKey, MasterKeyConfig
)
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo

_LOGGER = logging.getLogger(__name__)

_PROVIDER_ID = 'aws-kms'


@attr.s
class KMSMasterKeyProviderConfig(MasterKeyProviderConfig):
    """Configuration object for KMSMasterKeyProvider objects.

    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    """
    botocore_session = attr.ib(
        default=attr.Factory(botocore.session.Session),
        validator=attr.validators.instance_of(botocore.session.Session)
    )
    key_ids = attr.ib(
        default=attr.Factory(list),
        validator=attr.validators.instance_of(list)
    )
    region_names = attr.ib(
        default=attr.Factory(list),
        validator=attr.validators.instance_of(list)
    )


class KMSMasterKeyProvider(MasterKeyProvider):
    """Master Key Provider for KMS.

    >>> import aws_encryption_sdk
    >>> kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ... ])
    >>> kms_key_provider.add_master_key('arn:aws:kms:ap-northeast-1:4444444444444:alias/another-key')

    .. note::
        If no botocore_session is provided, the default botocore session will be used.

    .. note::
        If multiple AWS Identities are needed, one of two options are available:

        * Additional KMSMasterKeyProvider instances may be added to the primary MasterKeyProvider.

        * KMSMasterKey instances may be manually created and added to this KMSMasterKeyProvider.

    :param config: Configuration object (optional)
    :type config: aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig
    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    """
    provider_id = _PROVIDER_ID
    _config_class = KMSMasterKeyProviderConfig
    default_region = None

    def __init__(self, **kwargs):
        self._regional_clients = {}
        self._process_config()

    def _process_config(self):
        """Traverses the config and adds master keys and regional clients as needed."""
        if self.config.key_ids:
            self.add_master_keys_from_list(self.config.key_ids)
        if self.config.region_names:
            self.add_regional_clients_from_list(self.config.region_names)
            self.default_region = self.config.region_names[0]
        else:
            self.default_region = self.config.botocore_session.get_config_variable('region')
            if self.default_region is not None:
                self.add_regional_client(self.default_region)

    def add_regional_client(self, region_name):
        """Adds a regional client for the specified region if it does not already exist.

        :param str region_name: AWS Region ID (ex: us-east-1)
        """
        if region_name not in self._regional_clients:
            self._regional_clients[region_name] = boto3.session.Session(
                region_name=region_name,
                botocore_session=self.config.botocore_session
            ).client('kms')

    def add_regional_clients_from_list(self, region_names):
        """Adds multiple regional clients for the specified regions if they do not already exist.

        :param list region_names: List of regions for which to pre-populate clients
        """
        for region_name in region_names:
            self.add_regional_client(region_name)

    def _client(self, key_id):
        """Returns a Boto3 KMS client for the appropriate region.

        :param str key_id: KMS CMK ID
        """
        try:
            region_name = key_id.split(':', 4)[3]
            if self.default_region is None:
                self.default_region = region_name
        except IndexError:
            if self.default_region is None:
                raise UnknownRegionError(
                    'No default region found and no region determinable from key id: {}'.format(key_id)
                )
            region_name = self.default_region
        self.add_regional_client(region_name)
        return self._regional_clients[region_name]

    def _new_master_key(self, key_id):
        """Returns a KMSMasterKey for the specified key_id.

        :param bytes key_id: KMS CMK ID
        :returns: KMS Master Key based on key_id
        :rtype: aws_encryption_sdk.key_providers.kms.KMSMasterKey
        :raises InvalidKeyIdError: if key_id is not a valid KMS CMK ID to which this key provider has access
        """
        _key_id = to_str(key_id)  # KMS client requires str, not bytes
        return KMSMasterKey(config=KMSMasterKeyConfig(
            key_id=key_id,
            client=self._client(_key_id)
        ))


@attr.s
class KMSMasterKeyConfig(MasterKeyConfig):
    """Configuration object for MasterKey objects.

    :param str key_id: KMS CMK ID
    :param client: Boto3 KMS client
    :type client: botocore.client.KMS
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations
    """
    provider_id = _PROVIDER_ID
    client = attr.ib(validator=attr.validators.instance_of(botocore.client.BaseClient))
    grant_tokens = attr.ib(
        default=attr.Factory(list),
        validator=attr.validators.instance_of(list)
    )


class KMSMasterKey(MasterKey):
    """Master Key class for KMS CMKs.

    :param config: Configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.key_providers.kms.KMSMasterKeyConfig
    :param bytes key_id: KMS CMK ID
    :param client: Boto3 KMS client
    :type client: botocore.client.KMS
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations
    """
    provider_id = _PROVIDER_ID
    _config_class = KMSMasterKeyConfig

    def __init__(self, **kwargs):
        self._key_id = to_str(self.key_id)  # KMS client requires str, not bytes
        self.config.client.meta.config.user_agent = (
            'Botocore-KMSMasterKey/{version}/{botocore_version}'
        ).format(
            version=__version__,
            botocore_version=botocore.__version__
        )

    def _generate_data_key(self, algorithm, encryption_context=None):
        """Generates data key and returns plaintext and ciphertext of key.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to pass to KMS
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structure.DataKey
        """
        kms_params = {
            'KeyId': self._key_id,
            'NumberOfBytes': algorithm.kdf_input_len
        }
        if encryption_context is not None:
            kms_params['EncryptionContext'] = encryption_context
        if self.config.grant_tokens:
            kms_params['GrantTokens'] = self.config.grant_tokens
        # Catch any boto3 errors and normalize to expected EncryptKeyError
        try:
            response = self.config.client.generate_data_key(**kms_params)
            plaintext = response['Plaintext']
            ciphertext = response['CiphertextBlob']
            key_id = response['KeyId']
        except (ClientError, KeyError):
            raise GenerateKeyError('Master Key {key_id} unable to generate data key'.format(key_id=self._key_id))
        return DataKey(
            key_provider=MasterKeyInfo(
                provider_id=self.provider_id,
                key_info=key_id
            ),
            data_key=plaintext,
            encrypted_data_key=ciphertext
        )

    def _encrypt_data_key(self, data_key, algorithm, encryption_context=None):
        """Encrypts a data key and returns the ciphertext.

        :param data_key: Unencrypted data key
        :type data_key: :class:`aws_encryption_sdk.structure.RawDataKey`
            or :class:`aws_encryption_sdk.structure.DataKey`
        :param algorithm: Placeholder to maintain API compatibility with parent
        :param dict encryption_context: Encryption context to pass to KMS
        :returns: Data key containing encrypted data key
        :rtype: aws_encryption_sdk.structure.EncryptedDataKey
        :raises EncryptKeyError: if Master Key is unable to encrypt data key
        """
        kms_params = {
            'KeyId': self._key_id,
            'Plaintext': data_key.data_key
        }
        if encryption_context:
            kms_params['EncryptionContext'] = encryption_context
        if self.config.grant_tokens:
            kms_params['GrantTokens'] = self.config.grant_tokens
        # Catch any boto3 errors and normalize to expected EncryptKeyError
        try:
            response = self.config.client.encrypt(**kms_params)
            ciphertext = response['CiphertextBlob']
            key_id = response['KeyId']
        except (ClientError, KeyError):
            raise EncryptKeyError('Master Key {key_id} unable to encrypt data key'.format(key_id=self._key_id))
        return EncryptedDataKey(
            key_provider=MasterKeyInfo(
                provider_id=self.provider_id,
                key_info=key_id
            ),
            encrypted_data_key=ciphertext
        )

    def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context=None):
        """Decrypts an encrypted data key and returns the plaintext.

        :param data_key: Encrypted data key
        :type data_key: aws_encryption_sdk.structure.EncryptedDataKey
        :type algorithm: aws_encryption_sdk.internal.crypto.identifiers.Algorithm` (not used for KMS)
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Decrypted data key
        :rtype: aws_encryption_sdk.structure.DataKey
        :raises DecryptKeyError: if Master Key is unable to decrypt data key
        """
        kms_params = {
            'CiphertextBlob': encrypted_data_key.encrypted_data_key
        }
        if encryption_context:
            kms_params['EncryptionContext'] = encryption_context
        if self.config.grant_tokens:
            kms_params['GrantTokens'] = self.config.grant_tokens
        # Catch any boto3 errors and normalize to expected DecryptKeyError
        try:
            response = self.config.client.decrypt(**kms_params)
            plaintext = response['Plaintext']
        except (ClientError, KeyError):
            raise DecryptKeyError('Master Key {key_id} unable to decrypt data key'.format(key_id=self._key_id))
        return DataKey(
            key_provider=self.key_provider,
            data_key=plaintext,
            encrypted_data_key=encrypted_data_key.encrypted_data_key
        )
