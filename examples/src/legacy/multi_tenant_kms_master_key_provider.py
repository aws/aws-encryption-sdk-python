# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example showing KMS Master Key Providers that call AWS KMS with per-tenant credentials over one connection pool.

boto3 binds credentials to a client at construction,
and the KMS Master Key Providers construct their clients from a botocore Session;
so serving many tenants, each with their own credentials, normally means a Session and a KMS client per tenant.
Both are heavy objects.

The providers below instead construct a ``TenantKmsClient`` per region:
a few references to the tenant's credentials and one shared ``KmsTransport``,
which owns the only connection pool in the process.

See ``examples/src/multi_tenant/design.md`` for the options considered and the decisions made.
"""
import attr
import botocore.session
import six

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryAwsKmsMasterKeyProvider,
    KMSMasterKeyConfig,
    KMSMasterKeyProviderConfig,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
    MRKAwareKMSMasterKey,
    MRKAwareKMSMasterKeyConfig,
    MRKAwareStrictAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)

from ..multi_tenant import KmsTransport, TenantKmsClient

# The methods the KMS Master Keys call.
_REQUIRED_CLIENT_METHODS = ("generate_data_key", "encrypt", "decrypt")


def _is_kms_client(instance, attribute, value):  # pylint: disable=unused-argument
    """Accepts boto3 KMS clients and ``TenantKmsClient``s alike (an attrs validator)."""
    missing = [name for name in _REQUIRED_CLIENT_METHODS if not callable(getattr(value, name, None))]
    if missing:
        raise TypeError("'{}' must be a KMS client; missing {}".format(attribute.name, ", ".join(missing)))


def _is_instance_of(cls):
    """Requires an instance of ``cls``, for attributes that default to None only because attrs<18.2 lacks kw_only."""

    def _validate(instance, attribute, value):  # pylint: disable=unused-argument
        if not isinstance(value, cls):
            raise TypeError("'{}' must be a {} (got {!r})".format(attribute.name, cls.__name__, value))

    return _validate


def _has_frozen_credentials(instance, attribute, value):  # pylint: disable=unused-argument
    """Requires a ``botocore.credentials.Credentials`` (an attrs validator)."""
    if not callable(getattr(value, "get_frozen_credentials", None)):
        raise TypeError("'{}' must be a botocore.credentials.Credentials".format(attribute.name))


@attr.s(hash=True)
class TenantKmsMasterKeyConfig(KMSMasterKeyConfig):
    """``KMSMasterKeyConfig`` that accepts a ``TenantKmsClient``.

    Only ``client`` is overridden: its ``instance_of(BaseClient)`` validator is replaced,
    and it no longer constructs a boto3 client by default.
    """

    client = attr.ib(hash=True, default=None, validator=_is_kms_client)


@attr.s(hash=True)
class TenantMRKAwareKmsMasterKeyConfig(MRKAwareKMSMasterKeyConfig):
    """``MRKAwareKMSMasterKeyConfig`` that accepts a ``TenantKmsClient``."""

    client = attr.ib(hash=True, default=None, validator=_is_kms_client)


@attr.s(hash=True)
class TenantKmsMasterKeyProviderConfig(KMSMasterKeyProviderConfig):
    """``KMSMasterKeyProviderConfig`` that also carries the shared transport and the tenant's credentials.

    :param transport: The shared transport
    :type transport: KmsTransport
    :param credentials: The tenant's credentials
    :type credentials: botocore.credentials.Credentials
    :param dict endpoint_urls: Map of AWS Region to KMS endpoint override (optional)
    """

    transport = attr.ib(hash=True, default=None, validator=_is_instance_of(KmsTransport))
    credentials = attr.ib(hash=False, default=None, validator=_has_frozen_credentials)
    endpoint_urls = attr.ib(
        hash=False,
        default=attr.Factory(dict),
        validator=attr.validators.instance_of(dict),
    )


class _TenantKmsClientMixin(object):
    """Constructs a ``TenantKmsClient``, rather than a boto3 client, for each region."""

    _config_class = TenantKmsMasterKeyProviderConfig

    def add_regional_client(self, region_name):
        """Adds a ``TenantKmsClient`` for the specified region if it does not already exist.

        :param str region_name: AWS Region ID (ex: us-east-1)
        """
        if region_name not in self._regional_clients:
            client = TenantKmsClient(
                transport=self.config.transport,
                region_name=region_name,
                credentials=self.config.credentials,
                endpoint_url=self.config.endpoint_urls.get(region_name),
                user_agent_extra=self._user_agent_adding_config.user_agent_extra,
            )
            # _register_client wraps every method in meta.method_to_api_mapping,
            # removing this client from the cache if it raises a BotoCoreError.
            self._register_client(client, region_name)
            self._regional_clients[region_name] = client


class TenantStrictAwsKmsMasterKeyProvider(_TenantKmsClientMixin, StrictAwsKmsMasterKeyProvider):
    """``StrictAwsKmsMasterKeyProvider`` for one tenant, over a shared ``KmsTransport``."""

    master_key_config_class = TenantKmsMasterKeyConfig


class TenantMRKAwareStrictAwsKmsMasterKeyProvider(_TenantKmsClientMixin, MRKAwareStrictAwsKmsMasterKeyProvider):
    """``MRKAwareStrictAwsKmsMasterKeyProvider`` for one tenant, over a shared ``KmsTransport``."""

    master_key_config_class = TenantMRKAwareKmsMasterKeyConfig


class TenantDiscoveryAwsKmsMasterKeyProvider(_TenantKmsClientMixin, DiscoveryAwsKmsMasterKeyProvider):
    """``DiscoveryAwsKmsMasterKeyProvider`` for one tenant, over a shared ``KmsTransport``."""

    master_key_config_class = TenantKmsMasterKeyConfig


class TenantMRKAwareDiscoveryAwsKmsMasterKeyProvider(_TenantKmsClientMixin, MRKAwareDiscoveryAwsKmsMasterKeyProvider):
    """``MRKAwareDiscoveryAwsKmsMasterKeyProvider`` for one tenant, over a shared ``KmsTransport``."""

    master_key_config_class = TenantMRKAwareKmsMasterKeyConfig

    def _new_master_key_impl(self, key_id):
        """Same behavior as ``MRKAwareDiscoveryAwsKmsMasterKeyProvider._new_master_key_impl``.

        The parent constructs ``MRKAwareKMSMasterKeyConfig`` directly, ignoring ``master_key_config_class``;
        this override only substitutes the configuration class.
        """
        _key_id = key_id.decode("utf-8") if isinstance(key_id, bytes) else key_id
        arn = arn_from_str(_key_id)
        # A multi-Region key is used in the discovery region; any other key in the region of its ARN.
        if arn.resource_id.startswith("mrk"):
            arn.region = self.config.discovery_region
            _key_id = arn.to_string()
        return MRKAwareKMSMasterKey(
            config=self.master_key_config_class(
                key_id=_key_id, client=self._client(_key_id), grant_tokens=self.config.grant_tokens
            )
        )


def encrypt_decrypt(tenant_key_arns, tenant_credentials, source_plaintext, botocore_session=None):
    """Encrypts and decrypts a message for each tenant, with that tenant's KMS key and credentials.

    :param dict tenant_key_arns: Map of tenant name to the ARN of that tenant's KMS key
    :param dict tenant_credentials: Map of tenant name to that tenant's credentials
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: Session shared by every provider; it is only consulted for a default region (optional)
    :type botocore_session: botocore.session.Session
    """
    # 1. Create one transport for the whole process.
    #    It owns the only connection pool; every tenant's KMS requests are sent over it.
    transport = KmsTransport()

    # 2. Share one botocore Session across every provider.
    #    If none is given, each provider constructs its own Session, which is exactly the cost we are avoiding.
    if botocore_session is None:
        botocore_session = botocore.session.Session()

    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    try:
        for tenant, key_arn in six.iteritems(tenant_key_arns):
            # 3. Create a provider per tenant. It is cheap: its clients are TenantKmsClients.
            key_provider = TenantStrictAwsKmsMasterKeyProvider(
                key_ids=[key_arn],
                transport=transport,
                credentials=tenant_credentials[tenant],
                botocore_session=botocore_session,
            )

            encryption_context = {"tenant": tenant}
            ciphertext, encrypt_header = client.encrypt(
                source=source_plaintext, key_provider=key_provider, encryption_context=encryption_context
            )
            plaintext, decrypt_header = client.decrypt(source=ciphertext, key_provider=key_provider)

            assert plaintext == source_plaintext
            assert all(
                pair in decrypt_header.encryption_context.items()
                for pair in encrypt_header.encryption_context.items()
            )
    finally:
        # 4. Close the transport only when the application shuts down.
        #    It is shared by every tenant; this example owns it, and every tenant is done with it here.
        #    An application MUST NOT close it while any tenant's provider may still use it:
        #    in-flight requests complete, but every pooled connection is dropped,
        #    so every tenant pays a new TLS handshake on its next request.
        transport.close()
