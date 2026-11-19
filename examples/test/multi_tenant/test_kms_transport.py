# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the shared KMS transport."""
# pylint: disable=redefined-outer-name
from concurrent.futures import CancelledError

import botocore.exceptions
import pytest
import urllib3
from botocore.credentials import Credentials

from ...src.multi_tenant.kms_transport import KmsTransport, default_endpoint_url
from . import fake_kms

pytestmark = [pytest.mark.examples]

KEY_ARN = "arn:aws:kms:us-west-2:111122223333:key/11111111-1111-1111-1111-111111111111"
TENANT = Credentials("AKIATENANT", "secret")


class CountingCredentials(Credentials):
    """Count how often credentials are frozen; RefreshableCredentials refresh there."""

    def __init__(self, *args, **kwargs):
        """Start counting at zero."""
        super().__init__(*args, **kwargs)
        self.frozen = 0

    def get_frozen_credentials(self):
        """Count, then freeze."""
        self.frozen += 1
        return super().get_frozen_credentials()


@pytest.fixture
def transport():
    return KmsTransport(max_attempts=3)


@pytest.fixture
def kms(transport):
    fake = fake_kms.install(transport)
    fake.add_key(KEY_ARN, TENANT.access_key)
    return fake


def _gdk(transport, credentials=TENANT, **kwargs):
    body = {"KeyId": KEY_ARN, "NumberOfBytes": 32}
    return transport.call("GenerateDataKey", body, "us-west-2", credentials, **kwargs)


def test_signs_with_given_credentials_and_region(transport, kms):
    response, metadata = _gdk(transport)
    assert response["KeyId"] == KEY_ARN
    assert metadata["HTTPStatusCode"] == 200
    assert metadata["RequestId"] == "fake-request-id"
    assert metadata["RetryAttempts"] == 0
    assert kms.requests[0]["access_key"] == "AKIATENANT"
    assert kms.requests[0]["region"] == "us-west-2"
    assert kms.requests[0]["url"] == "https://kms.us-west-2.amazonaws.com"


@pytest.mark.parametrize("region, url", [
    ("us-west-2", "https://kms.us-west-2.amazonaws.com"),
    ("cn-north-1", "https://kms.cn-north-1.amazonaws.com.cn"),
])
def test_default_endpoint_url(region, url):
    assert default_endpoint_url(region) == url


def test_endpoint_override(transport, kms):
    _gdk(transport, endpoint_url="https://vpce-123.kms.us-west-2.vpce.amazonaws.com")
    assert kms.requests[0]["url"] == "https://vpce-123.kms.us-west-2.vpce.amazonaws.com"


@pytest.mark.parametrize("region", ["evil.example.com/", "us-west-2.evil.com", "US-WEST-2", "", "us-west-2/", None])
def test_rejects_regions_that_alter_the_host(transport, kms, region):
    with pytest.raises(ValueError):
        transport.call("Decrypt", {}, region, TENANT)
    assert not kms.requests


def test_user_agent_extra(transport, kms):
    _gdk(transport, user_agent_extra="AwsCryptographicMPL/Python")
    assert kms.requests[0]["user_agent"].endswith(" AwsCryptographicMPL/Python")


def test_client_error_strips_namespace(transport, kms):
    with pytest.raises(botocore.exceptions.ClientError) as excinfo:
        _gdk(transport, credentials=Credentials("AKIAOTHER", "secret"))
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"
    assert "AKIAOTHER" in excinfo.value.response["Error"]["Message"]
    assert excinfo.value.operation_name == "GenerateDataKey"
    # Not retryable
    assert len(kms.requests) == 1


@pytest.mark.parametrize("failure", [
    fake_kms.FakeResponse(500, {"__type": "KMSInternalException"}),
    fake_kms.FakeResponse(400, {"__type": "com.amazonaws.kms#ThrottlingException"}),
    fake_kms.FakeResponse(503, b"<html>proxy</html>"),
    urllib3.exceptions.ReadTimeoutError(None, "/", "timed out"),
    urllib3.exceptions.NewConnectionError(None, "refused"),
    urllib3.exceptions.ProtocolError("reset"),
    urllib3.exceptions.SSLError("handshake failed"),
])
def test_retries_then_succeeds_re_signing_each_attempt(transport, kms, failure):
    credentials = CountingCredentials("AKIATENANT", "secret")
    kms.scripted = [failure]
    response, metadata = _gdk(transport, credentials=credentials)
    assert response["KeyId"] == KEY_ARN
    assert metadata["RetryAttempts"] == 1
    assert len(kms.requests) == 2
    assert credentials.frozen == 2


def test_gives_up_after_max_attempts_on_service_error(transport, kms):
    kms.scripted = [fake_kms.FakeResponse(500, {"__type": "KMSInternalException", "message": "oops"})] * 3
    with pytest.raises(botocore.exceptions.ClientError) as excinfo:
        _gdk(transport)
    assert excinfo.value.response["Error"]["Code"] == "KMSInternalException"
    assert excinfo.value.response["ResponseMetadata"]["RetryAttempts"] == 2
    assert len(kms.requests) == 3


# The same mapping as botocore's URLLib3Session.send (botocore/httpsession.py).
@pytest.mark.parametrize("failure, expected", [
    (urllib3.exceptions.SSLError("certificate verify failed"), botocore.exceptions.SSLError),
    (urllib3.exceptions.NewConnectionError(None, "refused"), botocore.exceptions.EndpointConnectionError),
    (urllib3.exceptions.NameResolutionError("kms.example", None, "no such host"),
     botocore.exceptions.EndpointConnectionError),
    (urllib3.exceptions.ConnectTimeoutError(None, "timed out"), botocore.exceptions.ConnectTimeoutError),
    (urllib3.exceptions.ReadTimeoutError(None, "/", "timed out"), botocore.exceptions.ReadTimeoutError),
    (urllib3.exceptions.ProtocolError("reset"), botocore.exceptions.ConnectionClosedError),
    (urllib3.exceptions.LocationParseError("bad"), botocore.exceptions.HTTPClientError),
    (OSError("unexpected"), botocore.exceptions.HTTPClientError),
])
def test_transport_failures_are_botocore_errors_and_retried(transport, kms, failure, expected):
    kms.scripted = [failure] * 3
    with pytest.raises(botocore.exceptions.BotoCoreError) as excinfo:
        _gdk(transport)
    assert type(excinfo.value) is expected  # pylint: disable=unidiomatic-typecheck
    assert excinfo.value.__cause__ is failure
    assert len(kms.requests) == 3


def test_cancellation_is_not_wrapped_or_retried(transport, kms):
    kms.scripted = [CancelledError()]
    with pytest.raises(CancelledError):
        _gdk(transport)
    assert len(kms.requests) == 1


def test_missing_credentials(transport, kms):
    with pytest.raises(botocore.exceptions.NoCredentialsError):
        _gdk(transport, credentials=None)
    assert not kms.requests


def test_repr_and_close(transport, kms):  # pylint: disable=unused-argument
    assert repr(transport) == "KmsTransport(max_attempts=3)"
    with transport:
        pass


def test_max_attempts_must_be_positive():
    with pytest.raises(ValueError):
        KmsTransport(max_attempts=0)
