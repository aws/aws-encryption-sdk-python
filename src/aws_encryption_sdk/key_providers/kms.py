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
"""Master Key Providers for use with AWS KMS"""
import abc
import functools
import logging

import attr
import boto3
import botocore.client
import botocore.config
import botocore.session
import six
from botocore.exceptions import ClientError

from aws_encryption_sdk.exceptions import (
    ConfigMismatchError,
    DecryptKeyError,
    EncryptKeyError,
    GenerateKeyError,
    MasterKeyProviderError,
    UnknownRegionError,
)
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig, MasterKeyProvider, MasterKeyProviderConfig
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo

_LOGGER = logging.getLogger(__name__)

_PROVIDER_ID = "aws-kms"


def _region_from_key_id(key_id, default_region=None):
    """Determine the target region from a key ID, falling back to a default region if provided.

    :param str key_id: AWS KMS key ID
    :param str default_region: Region to use if no region found in key_id
    :returns: region name
    :rtype: str
    :raises UnknownRegionError: if no region found in key_id and no default_region provided
    """
    try:
        region_name = key_id.split(":", 4)[3]
    except IndexError:
        if default_region is None:
            raise UnknownRegionError(
                "No default region found and no region determinable from key id: {}".format(key_id)
            )
        region_name = default_region
    return region_name


@attr.s(hash=True)
class DiscoveryFilter(object):
    """DiscoveryFilter to control accounts and partitions that can be used by a KMS Master Key Provider.

    :param list account_ids: List of AWS Account Ids that are allowed to be used for decryption
    :param str partition: The AWS partition to which account_ids belong
    """

    account_ids = attr.ib(
        default=attr.Factory(tuple), hash=True, validator=attr.validators.instance_of(tuple), converter=tuple
    )
    partition = attr.ib(default=None, hash=True, validator=attr.validators.optional(attr.validators.instance_of(str)))


@attr.s(hash=True)
class KMSMasterKeyProviderConfig(MasterKeyProviderConfig):
    """Configuration object for KMSMasterKeyProvider objects.

    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    :param DiscoveryFilter discovery_filter: Filter indicating AWS accounts and partitions whose keys will be trusted
        for decryption
    """

    botocore_session = attr.ib(
        hash=True,
        default=attr.Factory(botocore.session.Session),
        validator=attr.validators.instance_of(botocore.session.Session),
    )
    key_ids = attr.ib(
        hash=True, default=attr.Factory(tuple), validator=attr.validators.instance_of(tuple), converter=tuple
    )
    region_names = attr.ib(
        hash=True, default=attr.Factory(tuple), validator=attr.validators.instance_of(tuple), converter=tuple
    )
    discovery_filter = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(DiscoveryFilter))
    )


@six.add_metaclass(abc.ABCMeta)
class BaseKMSMasterKeyProvider(MasterKeyProvider):
    """Master Key Provider for KMS.

    .. note::
        Cannot be instantiated directly. Callers should use one of the implementing classes.

    """

    provider_id = _PROVIDER_ID
    _config_class = KMSMasterKeyProviderConfig
    default_region = None

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Prepares mutable attributes."""
        self._regional_clients = {}
        self._process_config()

    @abc.abstractmethod
    def validate_config(self):
        """Validates the provided configuration.

        .. note::
            Must be implemented by specific KMSMasterKeyProvider implementations.
        """

    def _process_config(self):
        """Traverses the config and adds master keys and regional clients as needed."""
        self._user_agent_adding_config = botocore.config.Config(user_agent_extra=USER_AGENT_SUFFIX)

        self.validate_config()

        if self.config.region_names:
            self.add_regional_clients_from_list(self.config.region_names)
            self.default_region = self.config.region_names[0]
        else:
            self.default_region = self.config.botocore_session.get_config_variable("region")
            if self.default_region is not None:
                self.add_regional_client(self.default_region)

        if self.config.key_ids:
            self.add_master_keys_from_list(self.config.key_ids)

    def _wrap_client(self, region_name, method, *args, **kwargs):
        """Proxies all calls to a kms clients methods and removes misbehaving clients

        :param str region_name: AWS Region ID (ex: us-east-1)
        :param callable method: a method on the KMS client to proxy
        :param tuple args: list of arguments to pass to the provided ``method``
        :param dict kwargs: dictonary of keyword arguments to pass to the provided ``method``
        """
        try:
            return method(*args, **kwargs)
        except botocore.exceptions.BotoCoreError:
            self._regional_clients.pop(region_name)
            _LOGGER.error(
                'Removing regional client "%s" from cache due to BotoCoreError on %s call', region_name, method.__name__
            )
            raise

    def _register_client(self, client, region_name):
        """Uses functools.partial to wrap all methods on a client with the self._wrap_client method

        :param botocore.client.BaseClient client: the client to proxy
        :param str region_name: AWS Region ID (ex: us-east-1)
        """
        for item in client.meta.method_to_api_mapping:
            method = getattr(client, item)
            wrapped_method = functools.partial(self._wrap_client, region_name, method)
            setattr(client, item, wrapped_method)

    def add_regional_client(self, region_name):
        """Adds a regional client for the specified region if it does not already exist.

        :param str region_name: AWS Region ID (ex: us-east-1)
        """
        if region_name not in self._regional_clients:
            session = boto3.session.Session(botocore_session=self.config.botocore_session)
            client = session.client("kms", region_name=region_name, config=self._user_agent_adding_config)
            self._register_client(client, region_name)
            self._regional_clients[region_name] = client

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
        region_name = _region_from_key_id(key_id, self.default_region)
        self.add_regional_client(region_name)
        return self._regional_clients[region_name]

    def _new_master_key(self, key_id):
        """Returns a KMSMasterKey for the specified key_id.

        :param bytes key_id: KMS CMK ID
        :returns: KMS Master Key based on key_id
        :rtype: aws_encryption_sdk.key_providers.kms.KMSMasterKey
        :raises InvalidKeyIdError: if key_id is not a valid KMS CMK ID to which this key provider has access
        :raises MasterKeyProviderError: if this MasterKeyProvider is in discovery mode and key_id is not allowed
        """
        _key_id = to_str(key_id)  # KMS client requires str, not bytes

        if self.config.discovery_filter:
            arn = arn_from_str(_key_id)

            if (
                arn.partition != self.config.discovery_filter.partition
                or arn.account_id not in self.config.discovery_filter.account_ids
            ):
                raise MasterKeyProviderError("Key {} not allowed by this Master Key Provider".format(key_id))

        return KMSMasterKey(config=KMSMasterKeyConfig(key_id=key_id, client=self._client(_key_id)))


class StrictAwsKmsMasterKeyProvider(BaseKMSMasterKeyProvider):
    """Strict Master Key Provider for KMS. It is configured with an explicit list of AWS KMS master keys that
    should be used for encryption in decryption. On encryption, the plaintext will be encrypted with all configured
    master keys. On decryption, the ciphertext will be decrypted with the first master key that can decrypt. If the
    ciphertext is encrypted with a master key that was not explicitly configured, decryption will fail.

    >>> import aws_encryption_sdk
    >>> kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
    ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ... ])

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

    def __init__(self, **kwargs):
        """Sets configuration required by this provider type."""
        super(StrictAwsKmsMasterKeyProvider, self).__init__(**kwargs)

        self.vend_masterkey_on_decrypt = False

    def validate_config(self):
        """Validates the provided configuration."""
        if not self.config.key_ids:
            raise ConfigMismatchError("To enable strict mode you must provide key ids")

        for key_id in self.config.key_ids:
            if not key_id:
                raise ConfigMismatchError("Key ids must be valid AWS KMS ARNs")

        if self.config.discovery_filter:
            raise ConfigMismatchError("To enable discovery mode, use a DiscoveryAwsKmsMasterKeyProvider")


class DiscoveryAwsKmsMasterKeyProvider(BaseKMSMasterKeyProvider):
    """Discovery Master Key Provider for KMS. This can only be used for decryption. It is configured with an optional
     Discovery Filter containing AWS account ids and partitions that should be trusted for decryption. If a ciphertext
     was encrypted with an AWS KMS master key that matches an account and partition listed by this provider, decryption
     will succeed. Otherwise, decryption will fail. If no Discovery Filter is configured, the provider will attempt
     to decrypt any ciphertext created by an AWS KMS Master Key Provider.

    >>> import aws_encryption_sdk
    >>> kms_key_provider = aws_encryption_sdk.DiscoveryAwsKmsMasterKeyProvider(discovery_filter=DiscoveryFilter(
    ...     account_ids=['2222222222222', '3333333333333']
    ... )

    .. note::
        If no botocore_session is provided, the default botocore session will be used.

    :param config: Configuration object (optional)
    :type config: aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig
    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    """

    def __init__(self, **kwargs):
        """Sets configuration required by this provider type."""
        super(DiscoveryAwsKmsMasterKeyProvider, self).__init__(**kwargs)

        self.vend_masterkey_on_decrypt = True

    def validate_config(self):
        """Validates the provided configuration."""
        if self.config.key_ids:
            raise ConfigMismatchError(
                "To explicitly identify which keys should be used, use a " "StrictAwsKmsMasterKeyProvider."
            )

        if self.config.discovery_filter:
            if not self.config.discovery_filter.account_ids or not self.config.discovery_filter.partition:
                raise ConfigMismatchError(
                    "When specifying a discovery filter you must include both account ids and " "partition"
                )
            for account in self.config.discovery_filter.account_ids:
                if not account:
                    raise ConfigMismatchError(
                        "When specifying a discovery filter, account ids must be non-empty " "strings"
                    )


@attr.s(hash=True)
class KMSMasterKeyConfig(MasterKeyConfig):
    """Configuration object for MasterKey objects.

    :param str key_id: KMS CMK ID
    :param client: Boto3 KMS client
    :type client: botocore.client.KMS
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations
    """

    provider_id = _PROVIDER_ID
    client = attr.ib(hash=True, validator=attr.validators.instance_of(botocore.client.BaseClient))
    grant_tokens = attr.ib(
        hash=True, default=attr.Factory(tuple), validator=attr.validators.instance_of(tuple), converter=tuple
    )

    @client.default
    def client_default(self):
        """Create a client if one was not provided."""
        try:
            region_name = _region_from_key_id(to_str(self.key_id))
            kwargs = dict(region_name=region_name)
        except UnknownRegionError:
            kwargs = {}
        botocore_config = botocore.config.Config(user_agent_extra=USER_AGENT_SUFFIX)
        return boto3.session.Session(**kwargs).client("kms", config=botocore_config)


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

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Performs transformations needed for KMS."""
        self._key_id = to_str(self.key_id)  # KMS client requires str, not bytes

    def _generate_data_key(self, algorithm, encryption_context=None):
        """Generates data key and returns plaintext and ciphertext of key.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to pass to KMS
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """
        kms_params = {"KeyId": self._key_id, "NumberOfBytes": algorithm.kdf_input_len}
        if encryption_context is not None:
            kms_params["EncryptionContext"] = encryption_context
        if self.config.grant_tokens:
            kms_params["GrantTokens"] = self.config.grant_tokens
        # Catch any boto3 errors and normalize to expected EncryptKeyError
        try:
            response = self.config.client.generate_data_key(**kms_params)
            plaintext = response["Plaintext"]
            ciphertext = response["CiphertextBlob"]
            key_id = response["KeyId"]
        except (ClientError, KeyError):
            error_message = "Master Key {key_id} unable to generate data key".format(key_id=self._key_id)
            _LOGGER.exception(error_message)
            raise GenerateKeyError(error_message)
        return DataKey(
            key_provider=MasterKeyInfo(provider_id=self.provider_id, key_info=key_id),
            data_key=plaintext,
            encrypted_data_key=ciphertext,
        )

    def _encrypt_data_key(self, data_key, algorithm, encryption_context=None):
        """Encrypts a data key and returns the ciphertext.

        :param data_key: Unencrypted data key
        :type data_key: :class:`aws_encryption_sdk.structures.RawDataKey`
            or :class:`aws_encryption_sdk.structures.DataKey`
        :param algorithm: Placeholder to maintain API compatibility with parent
        :param dict encryption_context: Encryption context to pass to KMS
        :returns: Data key containing encrypted data key
        :rtype: aws_encryption_sdk.structures.EncryptedDataKey
        :raises EncryptKeyError: if Master Key is unable to encrypt data key
        """
        kms_params = {"KeyId": self._key_id, "Plaintext": data_key.data_key}
        if encryption_context:
            kms_params["EncryptionContext"] = encryption_context
        if self.config.grant_tokens:
            kms_params["GrantTokens"] = self.config.grant_tokens
        # Catch any boto3 errors and normalize to expected EncryptKeyError
        try:
            response = self.config.client.encrypt(**kms_params)
            ciphertext = response["CiphertextBlob"]
            key_id = response["KeyId"]
        except (ClientError, KeyError):
            error_message = "Master Key {key_id} unable to encrypt data key".format(key_id=self._key_id)
            _LOGGER.exception(error_message)
            raise EncryptKeyError(error_message)
        return EncryptedDataKey(
            key_provider=MasterKeyInfo(provider_id=self.provider_id, key_info=key_id), encrypted_data_key=ciphertext
        )

    def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context=None):
        """Decrypts an encrypted data key and returns the plaintext.

        :param data_key: Encrypted data key
        :type data_key: aws_encryption_sdk.structures.EncryptedDataKey
        :type algorithm: `aws_encryption_sdk.identifiers.Algorithm` (not used for KMS)
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        :raises DecryptKeyError: if Master Key is unable to decrypt data key
        """
        edk_key_id = to_str(encrypted_data_key.key_provider.key_info)
        if edk_key_id != self._key_id:
            raise DecryptKeyError(
                "Cannot decrypt EDK wrapped by key_id={}, because it does not match this "
                "provider's key_id={}".format(edk_key_id, self._key_id)
            )

        kms_params = {"CiphertextBlob": encrypted_data_key.encrypted_data_key, "KeyId": edk_key_id}
        if encryption_context:
            kms_params["EncryptionContext"] = encryption_context
        if self.config.grant_tokens:
            kms_params["GrantTokens"] = self.config.grant_tokens
        # Catch any boto3 errors and normalize to expected DecryptKeyError
        try:
            response = self.config.client.decrypt(**kms_params)

            returned_key_id = response["KeyId"]
            if returned_key_id != edk_key_id:
                error_message = "AWS KMS returned unexpected key_id {returned} (expected {key_id})".format(
                    returned=returned_key_id, key_id=edk_key_id
                )
                _LOGGER.exception(error_message)
                raise DecryptKeyError(error_message)
            plaintext = response["Plaintext"]
        except (ClientError, KeyError):
            error_message = "Master Key {key_id} unable to decrypt data key".format(key_id=self._key_id)
            _LOGGER.exception(error_message)
            raise DecryptKeyError(error_message)
        return DataKey(
            key_provider=self.key_provider, data_key=plaintext, encrypted_data_key=encrypted_data_key.encrypted_data_key
        )
