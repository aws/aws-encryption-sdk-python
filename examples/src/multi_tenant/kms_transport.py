# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One HTTP connection pool, signer, and logger for every tenant's AWS KMS requests.

See design.md in this directory for the options considered and the decisions made.

boto3 binds AWS credentials to a client when the client is constructed,
and every boto3 client owns its own connection pool.
``KmsTransport`` instead accepts the credentials with each request,
so one instance can serve every tenant in a process.

This module MUST NOT import the AWS Cryptographic Material Providers Library (MPL),
and MUST remain compatible with every Python version the AWS Encryption SDK supports,
as the legacy Master Key Provider examples use it without the MPL installed.
"""
import json
import logging
import random
import re
import time
from concurrent.futures import CancelledError

import botocore.auth
import botocore.awsrequest
import botocore.exceptions
import urllib3

_LOGGER = logging.getLogger(__name__)

_JSON_CONTENT_TYPE = "application/x-amz-json-1.1"
_TARGET_PREFIX = "TrentService."
_SIGNING_NAME = "kms"

# Lowercase letters, digits, and hyphens only.
# The region is interpolated into the endpoint's host name,
# and Discovery keyrings and providers take it from the ciphertext.
_REGION_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

_RETRYABLE_ERROR_CODES = frozenset(["ThrottlingException", "KMSInternalException", "DependencyTimeoutException"])
# The transport failures botocore's standard retry mode treats as transient
# (TransientRetryableChecker in botocore/retries/standard.py): every type _send raises except NoCredentialsError.
_RETRYABLE_TRANSPORT_ERRORS = (botocore.exceptions.ConnectionError, botocore.exceptions.HTTPClientError)
_MAX_BACKOFF_SECONDS = 20.0

# Jitter is not security sensitive; SystemRandom simply avoids a shared, seedable global.
_RANDOM = random.SystemRandom()

DEFAULT_USER_AGENT = "aws-encryption-sdk-python-multi-tenant-kms-example"


def default_endpoint_url(region_name):
    """Returns the public AWS KMS endpoint for a region.

    Only the ``aws`` and ``aws-cn`` partitions are supported;
    use an endpoint override for anything else (FIPS, VPC endpoints, other partitions).

    :param str region_name: AWS Region (ex: us-west-2)
    :rtype: str
    :raises ValueError: if ``region_name`` is not a syntactically valid region
    """
    validate_region_name(region_name)
    suffix = "amazonaws.com.cn" if region_name.startswith("cn-") else "amazonaws.com"
    return "https://kms.{region}.{suffix}".format(region=region_name, suffix=suffix)


def validate_region_name(region_name):
    """Rejects any region that could alter the endpoint's host name.

    :param str region_name: AWS Region (ex: us-west-2)
    :raises ValueError: if ``region_name`` is not lowercase letters, digits, and hyphens
    """
    if not isinstance(region_name, str) or not _REGION_PATTERN.match(region_name):
        raise ValueError("Invalid AWS region name: {!r}".format(region_name))


class KmsTransport(object):
    """Sends signed AWS KMS JSON protocol requests over one shared connection pool.

    One instance is intended per process; it is safe to share across threads.

    Unlike boto3, this transport ignores ``HTTPS_PROXY``, ``HTTP_PROXY``, and ``NO_PROXY``;
    proxies are out of scope for this example (see design.md).

    :param int max_pool_connections: Maximum connections kept per KMS endpoint
    :param float connect_timeout: Seconds to wait for a connection
    :param float read_timeout: Seconds to wait for a response
    :param int max_attempts: Total attempts per request, including the first
    :param str user_agent: User-Agent sent with every request
    """

    def __init__(
        self,
        max_pool_connections=50,
        connect_timeout=5.0,
        read_timeout=30.0,
        max_attempts=3,
        user_agent=DEFAULT_USER_AGENT,
    ):
        """Creates the connection pool."""
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._max_attempts = max_attempts
        self._user_agent = user_agent
        self._timeout = urllib3.Timeout(connect=connect_timeout, read=read_timeout)
        # urllib3's own retries are disabled; this class retries, so that each attempt is re-signed.
        self._pool = urllib3.PoolManager(maxsize=max_pool_connections, retries=False)

    def __repr__(self):
        """Describes the transport."""
        return "KmsTransport(max_attempts={})".format(self._max_attempts)

    def __enter__(self):
        """Returns this transport, which is closed on exit."""
        return self

    def __exit__(self, *exc_info):
        """Closes this transport."""
        self.close()

    def close(self):
        """Closes every pooled connection.

        The transport is shared by every tenant; close it only when the application shuts down.
        In-flight requests complete, but no connection is re-used afterwards,
        so closing it while tenants are still active costs every tenant a new TLS handshake.
        """
        self._pool.clear()

    def call(  # pylint: disable=too-many-arguments
        self, operation_name, body, region_name, credentials, endpoint_url=None, user_agent_extra=None
    ):
        """Calls a KMS operation, signing every attempt with ``credentials``.

        :param str operation_name: KMS operation name (ex: GenerateDataKey)
        :param dict body: JSON serializable request; blobs MUST already be base64 encoded
        :param str region_name: AWS Region to sign for (ex: us-west-2)
        :param credentials: The tenant's credentials
        :type credentials: botocore.credentials.Credentials
        :param str endpoint_url: Endpoint override (optional)
        :param str user_agent_extra: Appended to the User-Agent (optional)
        :returns: The parsed JSON response, and the response metadata
        :rtype: tuple(dict, dict)
        :raises botocore.exceptions.ClientError: if KMS returns an error
        :raises botocore.exceptions.BotoCoreError: if KMS cannot be reached after every attempt
        """
        validate_region_name(region_name)
        url = endpoint_url or default_endpoint_url(region_name)
        payload = json.dumps(body).encode("utf-8")
        user_agent = self._user_agent if not user_agent_extra else self._user_agent + " " + user_agent_extra

        attempt = 0
        while True:
            attempt += 1
            try:
                status, headers, data = self._send(
                    operation_name, url, payload, region_name, credentials, user_agent
                )
            except _RETRYABLE_TRANSPORT_ERRORS:
                if attempt >= self._max_attempts:
                    raise
                _LOGGER.debug("KMS %s attempt %d failed to reach %s; retrying", operation_name, attempt, url)
                self._backoff(attempt)
                continue

            metadata = {
                "RequestId": headers.get("x-amzn-requestid", ""),
                "HTTPStatusCode": status,
                "HTTPHeaders": headers,
                "RetryAttempts": attempt - 1,
            }

            if status == 200:
                return _parse_json(data), metadata

            error_response = _error_response(status, headers, data, metadata)
            code = error_response["Error"]["Code"]
            if attempt < self._max_attempts and (status >= 500 or code in _RETRYABLE_ERROR_CODES):
                _LOGGER.debug("KMS %s attempt %d returned %s; retrying", operation_name, attempt, code)
                self._backoff(attempt)
                continue
            raise botocore.exceptions.ClientError(error_response, operation_name)

    def _send(  # pylint: disable=too-many-arguments
        self, operation_name, url, payload, region_name, credentials, user_agent
    ):
        """Signs and sends one attempt.

        :returns: HTTP status, response headers (lowercase names), and response body
        :rtype: tuple(int, dict, bytes)
        """
        frozen = credentials.get_frozen_credentials() if credentials is not None else None
        if frozen is None or frozen.access_key is None:
            raise botocore.exceptions.NoCredentialsError()

        request = botocore.awsrequest.AWSRequest(
            method="POST",
            url=url,
            data=payload,
            headers={
                "Content-Type": _JSON_CONTENT_TYPE,
                "X-Amz-Target": _TARGET_PREFIX + operation_name,
                "User-Agent": user_agent,
            },
        )
        # SigV4Auth is a public botocore interface; it adds X-Amz-Date, X-Amz-Security-Token, and Authorization.
        botocore.auth.SigV4Auth(frozen, _SIGNING_NAME, region_name).add_auth(request)
        prepared = request.prepare()

        # The exception mapping below mirrors botocore's ``URLLib3Session.send`` (botocore/httpsession.py),
        # in the same order, so callers see the exception types boto3 would raise.
        # botocore also maps urllib3's ProxyError; proxies are out of scope (see design.md), so it cannot occur.
        try:
            response = self._pool.urlopen(
                "POST",
                prepared.url,
                body=prepared.body,
                headers=dict(prepared.headers.items()),
                timeout=self._timeout,
                retries=False,
                redirect=False,
                preload_content=True,
            )
        except urllib3.exceptions.SSLError as error:
            raise botocore.exceptions.SSLError(endpoint_url=url, error=error) from error
        except urllib3.exceptions.NewConnectionError as error:
            # Includes NameResolutionError. NewConnectionError subclasses ConnectTimeoutError; check it first.
            raise botocore.exceptions.EndpointConnectionError(endpoint_url=url, error=error) from error
        except urllib3.exceptions.ConnectTimeoutError as error:
            raise botocore.exceptions.ConnectTimeoutError(endpoint_url=url, error=error) from error
        except urllib3.exceptions.ReadTimeoutError as error:
            raise botocore.exceptions.ReadTimeoutError(endpoint_url=url, error=error) from error
        except urllib3.exceptions.ProtocolError as error:
            # The connection was established, then closed before a complete response was received.
            raise botocore.exceptions.ConnectionClosedError(endpoint_url=url, error=error) from error
        except CancelledError:
            raise
        except Exception as error:  # pylint: disable=broad-except
            raise botocore.exceptions.HTTPClientError(error=error) from error

        return response.status, {key.lower(): value for key, value in response.headers.items()}, response.data

    @staticmethod
    def _backoff(attempt):
        """Sleeps with full jitter exponential backoff, as botocore's standard retry mode does."""
        time.sleep(_RANDOM.uniform(0, min(_MAX_BACKOFF_SECONDS, 2 ** (attempt - 1))))


def _parse_json(data):
    """Parses a response body, treating an empty body as an empty object."""
    if not data:
        return {}
    try:
        return json.loads(data.decode("utf-8"))
    except ValueError:
        return {}


def _error_response(status, headers, data, metadata):
    """Builds the ``ClientError.response`` boto3 would build for a KMS error.

    KMS MAY qualify the error type with a namespace (``com.amazonaws.kms#NotFoundException``);
    the MPL maps errors by the unqualified code, so the namespace is removed.
    """
    parsed = _parse_json(data)
    code = parsed.get("__type") or headers.get("x-amzn-errortype") or ""
    code = code.split("#")[-1].split(":")[0] or str(status)
    message = parsed.get("message") or parsed.get("Message") or ""
    return {"Error": {"Code": code, "Message": message}, "ResponseMetadata": metadata}
