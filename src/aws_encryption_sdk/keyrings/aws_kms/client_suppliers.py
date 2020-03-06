# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AWS KMS client suppliers for use with AWS KMS keyring.

.. versionadded:: 1.5.0

"""
import logging

import attr
import six
from attr.validators import deep_iterable, instance_of
from botocore.client import BaseClient
from botocore.session import Session as BotocoreSession

from aws_encryption_sdk.exceptions import UnknownRegionError
from aws_encryption_sdk.internal.validators import value_is_not_a_string

from .client_cache import ClientCache

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Dict, Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

_LOGGER = logging.getLogger(__name__)
__all__ = ("ClientSupplier", "DefaultClientSupplier", "AllowRegionsClientSupplier", "DenyRegionsClientSupplier")


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

    :param botocore_session: botocore session to use when creating clients (optional)
    :type botocore_session: botocore.session.Session
    """

    _botocore_session = attr.ib(default=attr.Factory(BotocoreSession), validator=instance_of(BotocoreSession))

    def __attrs_post_init__(self):
        """Set up internal client cache."""
        self._cache = ClientCache(botocore_session=self._botocore_session)

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        """
        return self._cache.client(region_name=region_name, service="kms")


@attr.s
class AllowRegionsClientSupplier(ClientSupplier):
    """AWS KMS client supplier that only supplies clients for the specified regions.

    .. versionadded:: 1.5.0

    :param List[str] allowed_regions: Regions to allow
    :param botocore_session: botocore session to use when creating clients (optional)
    :type botocore_session: botocore.session.Session
    """

    allowed_regions = attr.ib(
        validator=(deep_iterable(member_validator=instance_of(six.string_types)), value_is_not_a_string)
    )
    _botocore_session = attr.ib(default=attr.Factory(BotocoreSession), validator=instance_of(BotocoreSession))

    def __attrs_post_init__(self):
        """Set up internal client supplier."""
        self._supplier = DefaultClientSupplier(botocore_session=self._botocore_session)

    def client(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        :raises UnknownRegionError: if a region is requested that is not in ``allowed_regions``
        """
        if region_name not in self.allowed_regions:
            raise UnknownRegionError("Unable to provide client for region '{}'".format(region_name))

        return self._supplier(region_name)


@attr.s
class DenyRegionsClientSupplier(ClientSupplier):
    """AWS KMS client supplier that supplies clients for any region except for the specified regions.

    .. versionadded:: 1.5.0

    :param List[str] denied_regions: Regions to deny
    :param botocore_session: Botocore session to use when creating clients (optional)
    :type botocore_session: botocore.session.Session
    """

    denied_regions = attr.ib(
        validator=(deep_iterable(member_validator=instance_of(six.string_types)), value_is_not_a_string)
    )
    _botocore_session = attr.ib(default=attr.Factory(BotocoreSession), validator=instance_of(BotocoreSession))

    def __attrs_post_init__(self):
        """Set up internal client supplier."""
        self._supplier = DefaultClientSupplier(botocore_session=self._botocore_session)

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        :raises UnknownRegionError: if a region is requested that is in ``denied_regions``
        """
        if region_name in self.denied_regions:
            raise UnknownRegionError("Unable to provide client for region '{}'".format(region_name))

        return self._supplier(region_name)
