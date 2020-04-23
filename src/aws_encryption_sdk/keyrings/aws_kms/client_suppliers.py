# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AWS KMS client suppliers for use with AWS KMS keyring.

.. versionadded:: 1.5.0

"""
import functools
import logging

import attr
import six
from attr.validators import deep_iterable, instance_of, is_callable, optional
from botocore.client import BaseClient
from botocore.config import Config as BotocoreConfig
from botocore.session import Session as BotocoreSession

from aws_encryption_sdk.exceptions import UnknownRegionError
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX
from aws_encryption_sdk.internal.validators import value_is_not_a_string

from ._client_cache import ClientCache

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, Union  # noqa pylint: disable=unused-import

    ClientSupplierType = Callable[[Union[None, str]], BaseClient]
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

_LOGGER = logging.getLogger(__name__)
__all__ = (
    "ClientSupplier",
    "ClientSupplierType",
    "DefaultClientSupplier",
    "AllowRegionsClientSupplier",
    "DenyRegionsClientSupplier",
)


class ClientSupplier(object):
    """Base class for client suppliers.

    .. versionadded:: 1.5.0

    """

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        """
        raise NotImplementedError("'ClientSupplier' is not callable")


@attr.s
class DefaultClientSupplier(ClientSupplier):
    """The default AWS KMS client supplier.
    Creates and caches clients for any region.

    .. versionadded:: 1.5.0

    If you want clients to have special credentials or other configuration,
    you can provide those with custom ``botocore`` Session and/or `Config`_ instances.

    .. _Config: https://botocore.amazonaws.com/v1/documentation/api/latest/reference/config.html

    .. code-block:: python

        from aws_encryption_sdk.keyrings.aws_kms.client_supplier import DefaultClientSupplier
        from botocore.session import Session
        from botocore.config import Config

        my_client_supplier = DefaultClientSupplier(
            botocore_session=Session(**_get_custom_credentials()),
            client_config=Config(connect_timeout=10),
        )

    :param botocore_session: Botocore session to use when creating clients (optional)
    :type botocore_session: botocore.session.Session
    :param client_config: Config to use when creating client (optional)
    :type client_config: botocore.config.Config
    """

    _botocore_session = attr.ib(default=attr.Factory(BotocoreSession), validator=instance_of(BotocoreSession))
    _client_config = attr.ib(
        default=attr.Factory(functools.partial(BotocoreConfig, user_agent_extra=USER_AGENT_SUFFIX)),
        validator=instance_of(BotocoreConfig),
    )

    def __attrs_post_init__(self):
        """Set up the internal cache."""
        self._client_cache = ClientCache(botocore_session=self._botocore_session, client_config=self._client_config)

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        """
        return self._client_cache.client(region_name=region_name, service="kms")


@attr.s
class AllowRegionsClientSupplier(ClientSupplier):
    """AWS KMS client supplier that only supplies clients for the specified regions.

    .. versionadded:: 1.5.0

    :param List[str] allowed_regions: Regions to allow
    :param ClientSupplier client_supplier: Client supplier to wrap (optional)
    """

    allowed_regions = attr.ib(
        validator=(deep_iterable(member_validator=instance_of((type(None), six.string_types))), value_is_not_a_string)
    )
    _client_supplier = attr.ib(default=attr.Factory(DefaultClientSupplier), validator=optional(is_callable()))

    def _check(self, region_name):
        # type: (Union[None, str]) -> None
        if region_name not in self.allowed_regions:
            raise UnknownRegionError("Unable to provide client for region '{}'".format(region_name))

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        :raises UnknownRegionError: if a region is requested that is not in ``allowed_regions``
        """
        self._check(region_name=region_name)

        client = self._client_supplier(region_name)

        self._check(region_name=client.meta.region_name)

        return client


@attr.s
class DenyRegionsClientSupplier(ClientSupplier):
    """AWS KMS client supplier that supplies clients for any region except for the specified regions.

    .. versionadded:: 1.5.0

    :param List[str] denied_regions: Regions to deny
    :param ClientSupplier client_supplier: Client supplier to wrap (optional)
    """

    denied_regions = attr.ib(
        validator=(deep_iterable(member_validator=instance_of((type(None), six.string_types))), value_is_not_a_string)
    )
    _client_supplier = attr.ib(default=attr.Factory(DefaultClientSupplier), validator=optional(is_callable()))

    def _check(self, region_name):
        # type: (Union[None, str]) -> None
        if region_name in self.denied_regions:
            raise UnknownRegionError("Unable to provide client for region '{}'".format(region_name))

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        :raises UnknownRegionError: if a region is requested that is in ``denied_regions``
        """
        self._check(region_name=region_name)

        client = self._client_supplier(region_name)

        self._check(region_name=client.meta.region_name)

        return client
