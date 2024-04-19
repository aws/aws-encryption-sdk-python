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
import itertools
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
    MalformedArnError,
    MasterKeyProviderError,
    UnknownRegionError,
)
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX
from aws_encryption_sdk.internal.arn import arn_from_str, is_valid_mrk_identifier
from aws_encryption_sdk.internal.deprecation import deprecated
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


def _key_resource_match(key1, key2):
    """Given two KMS key identifiers, determines whether they use the same key type resource ID.
    This method works with either bare key IDs or key ARNs; if an input cannot be parsed as an ARN
    it is assumed to be a bare key ID. Will output false if either input is an alias arn.
    """
    try:
        arn1 = arn_from_str(key1)
        if arn1.resource_type == "alias":
            return False
        resource_id_1 = arn1.resource_id
    except MalformedArnError:
        # We need to handle the case where the key id is not ARNs,
        # treat it as a bare id
        resource_id_1 = key1
    try:
        arn2 = arn_from_str(key2)
        if arn2.resource_type == "alias":
            return False
        resource_id_2 = arn2.resource_id
    except MalformedArnError:
        # We need to handle the case where the key id is not ARNs,
        # treat it as a bare id
        resource_id_2 = key2

    return resource_id_1 == resource_id_2


def _check_mrk_arns_equal(key1, key2):
    """Given two KMS key arns, determines whether they refer to related KMS MRKs.
    Returns an error if inputs are not equal and either input cannot be parsed as an ARN.
    """
    # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    # //# The caller MUST provide:
    if key1 == key2:
        # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        # //# If both identifiers are identical, this function MUST return "true".
        return True

    # Note that we will fail here if the input keys are not ARNs at this point
    arn1 = arn_from_str(key1)
    arn2 = arn_from_str(key2)

    if not arn1.indicates_multi_region_key() or not arn2.indicates_multi_region_key():
        # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        # //# Otherwise if either input is not identified as a multi-Region key
        # //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
        # //# this function MUST return "false".
        return False

    # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
    # //# Otherwise if both inputs are
    # //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
    # //# aws-kms-multi-region-key), this function MUST return the result of
    # //# comparing the "partition", "service", "accountId", "resourceType",
    # //# and "resource" parts of both ARN inputs.
    return (
        arn1.partition == arn2.partition
        and arn1.service == arn2.service
        and arn1.account_id == arn2.account_id
        and arn1.resource_type == arn2.resource_type
        and arn1.resource_id == arn2.resource_id
    )


@deprecated("Use DiscoveryFilter from the aws-cryptographic-material-providers library.")
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


@deprecated("Use KMS keyrings from the aws-cryptographic-material-providers library.")
@attr.s(hash=True)
class KMSMasterKeyConfig(MasterKeyConfig):
    """Configuration object for KMSMasterKey objects.

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


@deprecated("Use KMS keyrings from the aws-cryptographic-material-providers library.")
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
        kms_params = self._build_generate_data_key_request(algorithm, encryption_context)
        # Catch any boto3 errors and normalize to expected EncryptKeyError
        try:
            response = self.config.client.generate_data_key(**kms_params)
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
            # //# The response's "Plaintext" MUST be the plaintext in the output.
            plaintext = response["Plaintext"]
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
            # //# The response's cipher text blob MUST be used as the returned as the
            # //# ciphertext for the encrypted data key in the output.
            ciphertext = response["CiphertextBlob"]
            key_id = response["KeyId"]
        except (ClientError, KeyError):
            error_message = "Master Key {key_id} unable to generate data key".format(key_id=self._key_id)
            _LOGGER.exception(error_message)
            raise GenerateKeyError(error_message)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //# The response's "KeyId" MUST be valid.
        # arn_from_str will error if given an invalid key ARN
        try:
            key_id_str = to_str(key_id)
            arn_from_str(key_id_str)
        except MalformedArnError:
            error_message = "Retrieved an unexpected KeyID in response from KMS: {key_id}".format(key_id=key_id)
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
        kms_params = self._build_encrypt_request(data_key, encryption_context)
        # Catch any boto3 errors and normalize to expected EncryptKeyError
        try:
            response = self.config.client.encrypt(**kms_params)
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
            # //# The response's cipher text blob MUST be used as the "ciphertext" for the
            # //# encrypted data key.
            ciphertext = response["CiphertextBlob"]
            key_id = response["KeyId"]
        except (ClientError, KeyError):
            error_message = "Master Key {key_id} unable to encrypt data key".format(key_id=self._key_id)
            _LOGGER.exception(error_message)
            raise EncryptKeyError(error_message)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //# The AWS KMS Encrypt response MUST contain a valid "KeyId".
        # arn_from_str will error if given an invalid key ARN
        try:
            key_id_str = to_str(key_id)
            arn_from_str(key_id_str)
        except MalformedArnError:
            error_message = "Retrieved an unexpected KeyID in response from KMS: {key_id}".format(key_id=key_id)
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
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //# Additionally each provider info MUST be a valid AWS KMS ARN
        # //# (aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of
        # //# "key".
        edk_key_id = to_str(encrypted_data_key.key_provider.key_info)
        edk_arn = arn_from_str(edk_key_id)
        if not edk_arn.resource_type == "key":
            error_message = "AWS KMS Provider EDK contains unexpected key_id: {key_id}".format(key_id=edk_key_id)
            _LOGGER.exception(error_message)
            raise DecryptKeyError(error_message)

        self._validate_allowed_to_decrypt(edk_key_id)
        kms_params = self._build_decrypt_request(encrypted_data_key, encryption_context)
        # Catch any boto3 errors and normalize to expected DecryptKeyError
        try:
            response = self.config.client.decrypt(**kms_params)

            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
            # //# If the call succeeds then the response's "KeyId" MUST be equal to the
            # //# configured AWS KMS key identifier otherwise the function MUST collect
            # //# an error.
            # Note that Python logs but does not collect errors
            returned_key_id = response["KeyId"]
            if returned_key_id != self._key_id:
                error_message = "AWS KMS returned unexpected key_id {returned} (expected {key_id})".format(
                    returned=returned_key_id, key_id=self._key_id
                )
                _LOGGER.exception(error_message)
                raise DecryptKeyError(error_message)

            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
            # //# The response's "Plaintext"'s length MUST equal the length
            # //# required by the requested algorithm suite otherwise the function MUST
            # //# collect an error.
            # Note that Python logs but does not collect errors
            plaintext = response["Plaintext"]
            if len(plaintext) != algorithm.data_key_len:
                error_message = "Plaintext length ({len1}) does not match algorithm's expected length ({len2})".format(
                    len1=len(plaintext), len2=algorithm.data_key_len
                )
                raise DecryptKeyError(error_message)

        except (ClientError, KeyError):
            error_message = "Master Key {key_id} unable to decrypt data key".format(key_id=self._key_id)
            _LOGGER.exception(error_message)
            raise DecryptKeyError(error_message)
        return DataKey(
            key_provider=self.key_provider, data_key=plaintext, encrypted_data_key=encrypted_data_key.encrypted_data_key
        )

    def _build_decrypt_request(self, encrypted_data_key, encryption_context):
        """Prepares a decrypt request to send to KMS."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //# To decrypt the encrypted data key this master key MUST use the
        # //# configured AWS KMS client to make an AWS KMS Decrypt
        # //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        # //# API_Decrypt.html) request constructed as follows:
        kms_params = {"CiphertextBlob": encrypted_data_key.encrypted_data_key, "KeyId": self._key_id}
        if encryption_context:
            kms_params["EncryptionContext"] = encryption_context
        if self.config.grant_tokens:
            kms_params["GrantTokens"] = self.config.grant_tokens
        return kms_params

    def _build_generate_data_key_request(self, algorithm, encryption_context):
        """Prepares a generate data key request to send to KMS."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //# This master key MUST use the configured AWS KMS client to make an AWS KMS
        # //# GenerateDatakey (https://docs.aws.amazon.com/kms/latest/APIReference/
        # //# API_GenerateDataKey.html) request constructed as follows:
        kms_params = {"KeyId": self._key_id, "NumberOfBytes": algorithm.kdf_input_len}
        if encryption_context is not None:
            kms_params["EncryptionContext"] = encryption_context
        if self.config.grant_tokens:
            kms_params["GrantTokens"] = self.config.grant_tokens
        return kms_params

    def _build_encrypt_request(self, data_key, encryption_context):
        """Prepares an encrypt request to send to KMS."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //# The master key MUST use the configured AWS KMS client to make an AWS KMS Encrypt
        # //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        # //# API_Encrypt.html) request constructed as follows:
        kms_params = {"KeyId": self._key_id, "Plaintext": data_key.data_key}
        if encryption_context:
            kms_params["EncryptionContext"] = encryption_context
        if self.config.grant_tokens:
            kms_params["GrantTokens"] = self.config.grant_tokens
        return kms_params

    def _validate_allowed_to_decrypt(self, edk_key_id):
        """Checks that this provider is allowed to decrypt with the given key id."""
        if edk_key_id != self._key_id:
            raise DecryptKeyError(
                "Cannot decrypt EDK wrapped by key_id={}, because it does not match this "
                "provider's key_id={}".format(edk_key_id, self._key_id)
            )


@deprecated("Use KMS MRK keyrings from the aws-cryptographic-material-providers library.")
@attr.s(hash=True)
class MRKAwareKMSMasterKeyConfig(MasterKeyConfig):
    """Configuration object for MRKAwareKMSMasterKey objects. Mostly the same as KMSMasterKey, except the
    client parameter is required rather than optional.

    :param str key_id: KMS CMK ID
    :param client: Boto3 KMS client
    :type client: botocore.client.KMS
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations
    """

    provider_id = _PROVIDER_ID
    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    # //# The AWS KMS SDK client MUST not be null.
    client = attr.ib(hash=True, validator=attr.validators.instance_of(botocore.client.BaseClient))
    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    # //# The master key MUST be able to be
    # //# configured with an optional list of Grant Tokens.
    grant_tokens = attr.ib(
        hash=True, default=attr.Factory(tuple), validator=attr.validators.instance_of(tuple), converter=tuple
    )


@deprecated("Use KMS MRK keyrings from the aws-cryptographic-material-providers library.")
class MRKAwareKMSMasterKey(KMSMasterKey):
    """Master Key class for KMS MRKAware CMKs. The logic for this class is almost entirely the same as a normal
    KMSMasterKey ("single-region key"). The primary difference is that this class is more flexible in what ciphertexts
    it will try to decrypt; specifically, it knows how to treat related multi-region keys as identical for the
    purposes of checking whether it is allowed to decrypt.

    :param config: Configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.key_providers.kms.KMSMasterKeyConfig
    :param bytes key_id: KMS CMK ID
    :param client: Boto3 KMS client
    :type client: botocore.client.KMS
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations
    """

    # The following are true because MRKAwareKMSMasterKey transitively extends MasterKey:

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.5
    # //# MUST implement the Master Key Interface (../master-key-
    # //# interface.md#interface)

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.7
    # //# MUST be unchanged from the Master Key interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.8
    # //# MUST be unchanged from the Master Key interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    # //# The inputs MUST be the same as the Master Key Decrypt Data Key
    # //# (../master-key-interface.md#decrypt-data-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
    # //# The output MUST be the same as the Master Key Decrypt Data Key
    # //# (../master-key-interface.md#decrypt-data-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    # //# The inputs MUST be the same as the Master Key Generate Data Key
    # //# (../master-key-interface.md#generate-data-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
    # //# The output MUST be the same as the Master Key Generate Data Key
    # //# (../master-key-interface.md#generate-data-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
    # //# The inputs MUST be the same as the Master Key Encrypt Data Key
    # //# (../master-key-interface.md#encrypt-data-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
    # //# The output MUST be the same as the Master Key Encrypt Data Key
    # //# (../master-key-interface.md#encrypt-data-key) interface.

    provider_id = _PROVIDER_ID
    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
    # //# On initialization, the caller MUST provide:
    _config_class = MRKAwareKMSMasterKeyConfig

    def __init__(self, **kwargs):
        """Sets configuration required by this provider type."""
        super(MRKAwareKMSMasterKey, self).__init__(**kwargs)

        self.validate_config()

    def validate_config(self):
        """Validates the provided configuration."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
        # //# The AWS KMS
        # //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
        # //# valid-aws-kms-identifier).
        # If it starts with "arn:" ensure it's a valid arn by attempting to parse it.
        # Otherwise, we don't do any validation on bare ids or bare aliases.
        if self._key_id.startswith("arn:"):
            arn_from_str(self._key_id)

    def _validate_allowed_to_decrypt(self, edk_key_id):
        """Checks that this provider is allowed to decrypt with the given key id.

        Compared to the default KMS provider, this checks for MRK equality between the edk and the configured key id
        rather than strict string equality.
        """
        if not _check_mrk_arns_equal(edk_key_id, self._key_id):
            raise DecryptKeyError(
                "Cannot decrypt EDK wrapped by key_id={}, because it does not match this "
                "provider's key_id={}".format(edk_key_id, self._key_id)
            )

    def owns_data_key(self, data_key):
        """Determines if data_key object is owned by this MasterKey. This method overrides the method from the base
        class, because for MRKs we need to check for MRK equality on the key ids rather than exact string equality.

        :param data_key: Data key to evaluate
        :type data_key: :class:`aws_encryption_sdk.structures.DataKey`,
            :class:`aws_encryption_sdk.structures.RawDataKey`,
            or :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Boolean statement of ownership
        :rtype: bool
        """
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //# To match the encrypted data key's
        # //# provider ID MUST exactly match the value "aws-kms" and the the
        # //# function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-for-
        # //# decrypt.md#implementation) called with the configured AWS KMS key
        # //# identifier and the encrypted data key's provider info MUST return
        # //# "true".
        if data_key.key_provider.provider_id == self.key_provider.provider_id and _check_mrk_arns_equal(
            to_str(data_key.key_provider.key_info), to_str(self.key_provider.key_info)
        ):
            return True
        return False


@deprecated("Use KMS keyrings from the aws-cryptographic-material-providers library.")
@attr.s(hash=True)
class KMSMasterKeyProviderConfig(MasterKeyProviderConfig):
    """Configuration object for KMSMasterKeyProvider objects.

    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    :param list grant_tokens: List of grant tokens to pass to KMS on CMK operations
    :param DiscoveryFilter discovery_filter: Filter indicating AWS accounts and partitions whose keys will be trusted
        for decryption
    :param str discovery_region: The region to be used for discovery for MRK-aware providers
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
    grant_tokens = attr.ib(
        hash=True, default=attr.Factory(tuple), validator=attr.validators.instance_of(tuple), converter=tuple
    )
    discovery_filter = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(DiscoveryFilter))
    )
    discovery_region = attr.ib(
        hash=True, default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types))
    )


@deprecated("Use KMS keyrings from the aws-cryptographic-material-providers library.")
@six.add_metaclass(abc.ABCMeta)
class BaseKMSMasterKeyProvider(MasterKeyProvider):
    """Master Key Provider for KMS.

    .. note::
        Cannot be instantiated directly. Callers should use one of the implementing classes.
    """

    # The following are true because both MRKAwareDiscoveryAwsKmsMasterKeyProvider
    # and MRKAwareDiscoveryAwsKmsMasterKeyProvider transitively extend BaseKMSMasterKeyProvider,
    # which extends MasterKeyProvider

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.5
    # //# MUST implement the Master Key Provider Interface (../master-key-
    # //# provider-interface.md#interface)

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    # //# The input MUST be the same as the Master Key Provider Get Master Key
    # //# (../master-key-provider-interface.md#get-master-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    # //# The output MUST be the same as the Master Key Provider Get Master Key
    # //# (../master-key-provider-interface.md#get-master-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    # //# The input MUST be the same as the Master Key Provider Get Master Keys
    # //# For Encryption (../master-key-provider-interface.md#get-master-keys-
    # //# for-encryption) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    # //# The output MUST be the same as the Master Key Provider Get Master
    # //# Keys For Encryption (../master-key-provider-interface.md#get-master-
    # //# keys-for-encryption) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
    # //# The input MUST be the same as the Master Key Provider Decrypt Data
    # //# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
    # //# The output MUST be the same as the Master Key Provider Decrypt Data
    # //# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

    provider_id = _PROVIDER_ID
    _config_class = KMSMasterKeyProviderConfig
    default_region = None
    master_key_class = KMSMasterKey
    master_key_config_class = KMSMasterKeyConfig

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

        if self.config.region_names:
            self.add_regional_clients_from_list(self.config.region_names)
            self.default_region = self.config.region_names[0]
        else:
            self.default_region = self.config.botocore_session.get_config_variable("region")
            if self.default_region is not None:
                self.add_regional_client(self.default_region)

        self.validate_config()

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
        # //# If the configured mode is strict this function MUST return a
        # //# list of master keys obtained by calling Get Master Key (aws-kms-mrk-
        # //# aware-master-key-provider.md#get-master-key) for each AWS KMS key
        # //# identifier in the configured key ids
        # Note that Python creates the keys to be used for encryption on init of MKPs
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
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //= type=exception
        # //# If the requested AWS KMS key identifier is not a well formed ARN the
        # //# AWS Region MUST be the configured default region this SHOULD be
        # //# obtained from the AWS SDK.
        # _region_from_key_id only does a ':' split and does not determine
        # whether an ARN may otherwise we well formed. This results in
        # the region "us-west-2" being used for input "not:an:arn:us-west-2"
        # instead of the default region.
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
                # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
                # //# In discovery mode if a discovery filter is configured the requested AWS
                # //# KMS key ARN's "partition" MUST match the discovery filter's
                # //# "partition" and the AWS KMS key ARN's "account" MUST exist in the
                # //# discovery filter's account id set.
                raise MasterKeyProviderError("Key {} not allowed by this Master Key Provider".format(key_id))
        return self._new_master_key_impl(key_id)

    def _new_master_key_impl(self, key_id):
        """The actual creation of new master keys. Separated out from _new_master_key so that we can share the
        validation logic while also allowing subclasses to implement different logic for instantiation of the key
        itself.
        """
        _key_id = to_str(key_id)  # KMS client requires str, not bytes

        return self.master_key_class(
            config=self.master_key_config_class(
                key_id=key_id, client=self._client(_key_id), grant_tokens=self.config.grant_tokens
            )
        )


@deprecated("Use KMS keyrings from the aws-cryptographic-material-providers library.")
class StrictAwsKmsMasterKeyProvider(BaseKMSMasterKeyProvider):
    """Strict Master Key Provider for KMS. It is configured with an explicit list of AWS KMS master keys that
    should be used for encryption and decryption. On encryption, the plaintext will be encrypted with all configured
    master keys. On decryption, it only attempts to decrypt ciphertexts that have been wrapped with a CMK that
    matches one of the configured CMK ARNs. If the ciphertext is encrypted with a master key that was not
    explicitly configured, decryption will fail. To create a StrictAwsKmsMasterKeyProvider you must provide
    one or more CMKs. For providers that will only be used for encryption, you can use any valid KMS key
    identifier. For providers that will be used for decryption, you must use the key ARN; key ids, alias names, and
    alias ARNs are not supported.

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
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
            # //# The key id list MUST NOT be empty or null in strict mode.
            raise ConfigMismatchError("To enable strict mode you must provide key ids")

        for key_id in self.config.key_ids:
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
            # //# The key id list MUST NOT contain any null or empty string values.
            if not key_id:
                raise ConfigMismatchError("Key ids must be valid AWS KMS ARNs")

        if self.config.discovery_filter:
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
            # //# A discovery filter MUST NOT be configured in strict mode.
            raise ConfigMismatchError("To enable discovery mode, use a DiscoveryAwsKmsMasterKeyProvider")

        if self.config.discovery_region:
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
            # //# A default MRK Region MUST NOT be configured in strict mode.
            raise ConfigMismatchError(
                "To enable MRK-aware discovery mode, use a MRKAwareDiscoveryAwsKmsMasterKeyProvider"
            )


@deprecated("Use KMS MRK keyrings from the aws-cryptographic-material-providers library.")
class MRKAwareStrictAwsKmsMasterKeyProvider(StrictAwsKmsMasterKeyProvider):
    """A Strict Master Key Provider for KMS that has smarts for handling Multi-Region keys.

    TODO MORE

    :param config: Configuration object (optional)
    :type config: aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig
    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    """

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
    # //# In strict mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
    # //# master-key.md) MUST be returned configured with
    # This MKP returns an AWS KMS MRK Aware Master Key, however the MK
    # it returns is based on configured key ID with clients that match
    # those configured key's regions. Python doesn't use a regional client
    # supplier, and the MRK matching logic occurs as part of owns_data_key in the MK.
    master_key_class = MRKAwareKMSMasterKey
    master_key_config_class = MRKAwareKMSMasterKeyConfig

    def __init__(self, **kwargs):
        """Sets configuration required by this provider type."""
        super(MRKAwareStrictAwsKmsMasterKeyProvider, self).__init__(**kwargs)

        self.validate_unique_mrks()

    def validate_unique_mrks(self):
        """Make sure the set of configured key ids does not contain any related MRKs"""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //# All AWS KMS
        # //# key identifiers are be passed to Assert AWS KMS MRK are unique (aws-
        # //# kms-mrk-are-unique.md#Implementation) and the function MUST return
        # //# success.

        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //# The caller MUST provide:

        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //# If the list does not contain any multi-Region keys (aws-kms-key-
        # //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
        # //# exit successfully.
        mrk_identifiers = filter(is_valid_mrk_identifier, self.config.key_ids)
        duplicate_ids = set()
        for key1, key2 in itertools.combinations(mrk_identifiers, 2):
            if key1 in duplicate_ids and key2 in duplicate_ids:
                pass
            if _key_resource_match(key1, key2):
                if key1 not in duplicate_ids:
                    duplicate_ids.add(key1)
                if key2 not in duplicate_ids:
                    duplicate_ids.add(key2)

        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //# If there are zero duplicate resource ids between the multi-region
        # //# keys, this function MUST exit successfully

        # //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
        # //# If any duplicate multi-region resource ids exist, this function MUST
        # //# yield an error that includes all identifiers with duplicate resource
        # //# ids not only the first duplicate found.
        if len(duplicate_ids) > 0:
            raise ConfigMismatchError(
                "Configured key ids must be unique. Found related MRKs: {keys}".format(keys=", ".join(duplicate_ids))
            )


@deprecated("Use KMS discovery keyrings from the aws-cryptographic-material-providers library.")
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
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
            # //# The key id list MUST be empty in discovery mode.
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

        if self.config.discovery_region:
            raise ConfigMismatchError(
                "To enable MRK-aware discovery mode, use a MRKAwareDiscoveryAwsKmsMasterKeyProvider."
            )


@deprecated("Use KMS MRK keyrings from the aws-cryptographic-material-providers library.")
class MRKAwareDiscoveryAwsKmsMasterKeyProvider(DiscoveryAwsKmsMasterKeyProvider):
    """Discovery Master Key Provider for KMS that has smarts for handling Multi-Region keys

    TODO MORE

    .. note::
        If no botocore_session is provided, the default botocore session will be used.

    :param config: Configuration object (optional)
    :type config: aws_encryption_sdk.key_providers.kms.KMSMasterKeyProviderConfig
    :param botocore_session: botocore session object (optional)
    :type botocore_session: botocore.session.Session
    :param list key_ids: List of KMS CMK IDs with which to pre-populate provider (optional)
    :param list region_names: List of regions for which to pre-populate clients (optional)
    """

    # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
    # //# If the configured mode is discovery the function MUST return an empty
    # //# list.
    # This is true due to behaviors that MRKAwareDiscoveryAwsKmsMasterKeyProvider extend
    # Note that Python creates the keys to be used for encryption on init of KMS MKPs,
    # so this MKP will vend no encrypt keys as no key IDs are configured.

    def validate_config(self):
        """Validates the provided configuration."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
        # //# In discovery mode
        # //# if a default MRK Region is not configured the AWS SDK Default Region
        # //# MUST be used.
        if not self.config.discovery_region:
            if not self.default_region:
                # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
                # //# If an AWS SDK Default Region can not be obtained
                # //# initialization MUST fail.
                raise ConfigMismatchError(
                    "Failed to determine default discovery region; please provide an explicit discovery_region"
                )
            self.config.discovery_region = self.default_region

    def _new_master_key_impl(self, key_id):
        """Creation of new master keys. Compared to the base class, this class has smarts to use either the configured
        discovery region or, if not present, the default SDK region, to create new keys.
        """
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //# In discovery mode, the requested
        # //# AWS KMS key identifier MUST be a well formed AWS KMS ARN.
        _key_id = to_str(key_id)
        arn = arn_from_str(_key_id)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
        # //# In discovery mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
        # //# master-key.md) MUST be returned configured with
        # Note that in the MRK case we ensure the key ID passed along has the discovery region,
        # and in both cases _client(...) will ensure that a client is created that matches the key's region.

        if not arn.resource_id.startswith("mrk"):
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            # //# Otherwise if the requested AWS KMS key
            # //# identifier is identified as a multi-Region key (aws-kms-key-
            # //# arn.md#identifying-an-aws-kms-multi-region-key), then AWS Region MUST
            # //# be the region from the AWS KMS key ARN stored in the provider info
            # //# from the encrypted data key.
            # Note that this could return a normal KMSMasterKey and retain the same behavior,
            # however we opt to follow the spec here in order to bias towards consistency between
            # implementations.
            return MRKAwareKMSMasterKey(
                config=MRKAwareKMSMasterKeyConfig(
                    key_id=_key_id, client=self._client(_key_id), grant_tokens=self.config.grant_tokens
                )
            )
        else:
            # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
            # //# Otherwise if the mode is discovery then
            # //# the AWS Region MUST be the discovery MRK region.
            arn.region = self.config.discovery_region
            new_key_id = arn.to_string()

            return MRKAwareKMSMasterKey(
                config=MRKAwareKMSMasterKeyConfig(
                    key_id=new_key_id, client=self._client(new_key_id), grant_tokens=self.config.grant_tokens
                )
            )
