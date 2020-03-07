# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""boto3 client cache for use by client suppliers.

.. versionadded:: 1.5.0

"""
import functools
import logging

import attr
from attr.validators import instance_of
from boto3.session import Session as Boto3Session
from botocore.client import BaseClient
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError
from botocore.session import Session as BotocoreSession

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

_LOGGER = logging.getLogger(__name__)
__all__ = ("ClientCache",)


@attr.s
class ClientCache(object):
    """Provide boto3 clients regional clients, caching by region.

    Any clients that throw an error when used are immediately removed from the cache.

    .. versionadded:: 1.5.0

    :param botocore_session: Botocore session to use when creating clients
    :type botocore_session: botocore.session.Session
    :param client_config: Config to use when creating client
    :type client_config: botocore.config.Config
    """

    _botocore_session = attr.ib(validator=instance_of(BotocoreSession))
    _client_config = attr.ib(validator=instance_of(BotocoreConfig))

    def __attrs_post_init__(self):
        """Set up internal cache."""
        self._cache = {}  # type: Dict[str, BaseClient]

    def _wrap_client_method(self, region_name, method, *args, **kwargs):
        """Proxy a call to a boto3 client method and remove any misbehaving clients from the cache.

        :param str region_name: Client region name
        :param Callable method: Method on the boto3 client to proxy
        :param Tuple args: Positional arguments to pass to ``method``
        :param Dict kwargs: Named arguments to pass to ``method``
        :returns: result of
        """
        try:
            return method(*args, **kwargs)
        except BotoCoreError as error:
            try:
                del self._cache[region_name]
            except KeyError:
                pass
            _LOGGER.exception(
                'Removing client "%s" from cache due to BotoCoreError on %s call', region_name, method.__name__
            )
            raise error

    def _patch_client(self, client):
        # type: (BaseClient) -> BaseClient
        """Patch a boto3 client, wrapping every API call in ``_wrap_client_method``.

        :param BaseClient client: boto3 client to patch
        :returns: patched client
        """
        for method_name in client.meta.method_to_api_mapping:
            method = getattr(client, method_name)
            wrapped_method = functools.partial(self._wrap_client_method, client.meta.region_name, method)
            setattr(client, method_name, wrapped_method)

        return client

    def _add_client(self, region_name, service):
        # type: (str, str) -> BaseClient
        """Make a new client and add it to the internal cache.

        :param str region_name: Client region
        :param str service: Client service
        :returns: New client, now in cache
        :rtype: botocore.client.BaseClient
        """
        client = Boto3Session(botocore_session=self._botocore_session).client(
            service_name=service, region_name=region_name, config=self._client_config
        )
        patched_client = self._patch_client(client)
        self._cache[region_name] = patched_client
        return client

    def client(self, region_name, service):
        # type: (str, str) -> BaseClient
        """Get a client for the specified region and service.

        Generate a new client if needed.
        Otherwise, retrieve an existing client from the internal cache.

        :param str region_name: Client region
        :param str service: Client service
        :rtype: botocore.client.BaseClient
        """
        try:
            return self._cache[region_name]
        except KeyError:
            return self._add_client(region_name, service)
