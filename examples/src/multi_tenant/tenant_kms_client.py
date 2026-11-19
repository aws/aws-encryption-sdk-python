# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A lightweight, boto3 shaped, AWS KMS client bound to one tenant's credentials.

See design.md in this directory for the options considered and the decisions made.

A ``TenantKmsClient`` holds a reference to a shared ``KmsTransport``,
an AWS Region, and the tenant's credentials; nothing else.
Construct as many as there are tenants; they share one connection pool.

It implements the KMS operations used by the AWS KMS Keyring, the AWS KMS Key Store,
and the KMS Master Key Providers, accepting and returning what boto3's KMS client accepts and returns:

* ``generate_data_key``
* ``generate_data_key_without_plaintext``
* ``encrypt``
* ``decrypt``
* ``re_encrypt``

This module MUST NOT import the AWS Cryptographic Material Providers Library (MPL).
"""
import base64
import collections

import botocore.exceptions

from .kms_transport import KmsTransport, validate_region_name

_Operation = collections.namedtuple("_Operation", ("api_name", "required", "optional", "input_blobs"))

# Response members that are blobs, and are base64 encoded on the wire.
_OUTPUT_BLOBS = ("CiphertextBlob", "Plaintext", "CiphertextForRecipient")

_OPERATIONS = {
    "generate_data_key": _Operation(
        api_name="GenerateDataKey",
        required=("KeyId",),
        optional=("EncryptionContext", "NumberOfBytes", "KeySpec", "GrantTokens", "DryRun"),
        input_blobs=(),
    ),
    "generate_data_key_without_plaintext": _Operation(
        api_name="GenerateDataKeyWithoutPlaintext",
        required=("KeyId",),
        optional=("EncryptionContext", "NumberOfBytes", "KeySpec", "GrantTokens", "DryRun"),
        input_blobs=(),
    ),
    "encrypt": _Operation(
        api_name="Encrypt",
        required=("KeyId", "Plaintext"),
        optional=("EncryptionContext", "GrantTokens", "EncryptionAlgorithm", "DryRun"),
        input_blobs=("Plaintext",),
    ),
    "decrypt": _Operation(
        api_name="Decrypt",
        required=("CiphertextBlob",),
        optional=("EncryptionContext", "GrantTokens", "KeyId", "EncryptionAlgorithm", "DryRun"),
        input_blobs=("CiphertextBlob",),
    ),
    "re_encrypt": _Operation(
        api_name="ReEncrypt",
        required=("CiphertextBlob", "DestinationKeyId"),
        optional=(
            "SourceEncryptionContext",
            "SourceKeyId",
            "DestinationEncryptionContext",
            "SourceEncryptionAlgorithm",
            "DestinationEncryptionAlgorithm",
            "GrantTokens",
            "DryRun",
        ),
        input_blobs=("CiphertextBlob",),
    ),
}

#: The boto3 method names this client implements, as the KMS Master Key Provider's ``_register_client`` expects.
METHOD_TO_API_MAPPING = {name: operation.api_name for name, operation in _OPERATIONS.items()}


class _ClientConfig(object):
    """The subset of ``botocore.config.Config`` the MPL touches.

    The MPL appends its user agent to ``user_agent_extra`` when a keyring or key store is constructed,
    so it is read on every request rather than at construction.
    """

    def __init__(self, user_agent_extra=None):
        self.user_agent_extra = user_agent_extra


class _ClientMeta(object):
    """The subset of ``botocore.client.ClientMeta`` the MPL and the KMS Master Key Providers touch."""

    def __init__(self, region_name, endpoint_url, user_agent_extra):
        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self.config = _ClientConfig(user_agent_extra)
        self.method_to_api_mapping = dict(METHOD_TO_API_MAPPING)
        self.service_model = None


class TenantKmsClient(object):
    """An AWS KMS client for one tenant in one region, sending requests over a shared ``KmsTransport``.

    :param transport: The shared transport
    :type transport: KmsTransport
    :param str region_name: AWS Region (ex: us-west-2)
    :param credentials: The tenant's credentials; ``RefreshableCredentials`` are refreshed as needed
    :type credentials: botocore.credentials.Credentials
    :param str endpoint_url: Endpoint override (optional)
    :param str user_agent_extra: Appended to the User-Agent (optional)
    """

    def __init__(  # pylint: disable=too-many-arguments
        self, transport, region_name, credentials, endpoint_url=None, user_agent_extra=None
    ):
        """Validates and stores the transport, region, and credentials."""
        if not isinstance(transport, KmsTransport):
            raise TypeError("transport must be a KmsTransport")
        validate_region_name(region_name)
        if not callable(getattr(credentials, "get_frozen_credentials", None)):
            raise TypeError("credentials must be a botocore.credentials.Credentials")
        self._transport = transport
        self._credentials = credentials
        self.meta = _ClientMeta(region_name, endpoint_url, user_agent_extra)

    def __repr__(self):
        """Describes the client's region and endpoint."""
        # Never include the credentials; ESDK configuration objects include their client in their own repr.
        return "TenantKmsClient(region_name={!r}, endpoint_url={!r})".format(
            self.meta.region_name, self.meta.endpoint_url
        )

    def generate_data_key(self, **kwargs):
        """Calls ``kms:GenerateDataKey``; see boto3's ``KMS.Client.generate_data_key``."""
        return self._call("generate_data_key", kwargs)

    def generate_data_key_without_plaintext(self, **kwargs):
        """Calls ``kms:GenerateDataKeyWithoutPlaintext``.

        See boto3's ``KMS.Client.generate_data_key_without_plaintext``.
        """
        return self._call("generate_data_key_without_plaintext", kwargs)

    def encrypt(self, **kwargs):
        """Calls ``kms:Encrypt``; see boto3's ``KMS.Client.encrypt``."""
        return self._call("encrypt", kwargs)

    def decrypt(self, **kwargs):
        """Calls ``kms:Decrypt``; see boto3's ``KMS.Client.decrypt``."""
        return self._call("decrypt", kwargs)

    def re_encrypt(self, **kwargs):
        """Calls ``kms:ReEncrypt``; see boto3's ``KMS.Client.re_encrypt``."""
        return self._call("re_encrypt", kwargs)

    def _call(self, method_name, params):
        operation = _OPERATIONS[method_name]
        body = _serialize(operation, params)
        response, metadata = self._transport.call(
            operation_name=operation.api_name,
            body=body,
            region_name=self.meta.region_name,
            credentials=self._credentials,
            endpoint_url=self.meta.endpoint_url,
            user_agent_extra=self.meta.config.user_agent_extra,
        )
        for member in _OUTPUT_BLOBS:
            if member in response:
                response[member] = base64.b64decode(response[member])
        response["ResponseMetadata"] = metadata
        return response


def _serialize(operation, params):
    """Validates boto3 style parameters and converts them to the KMS JSON protocol.

    :raises botocore.exceptions.ParamValidationError: as boto3 would, before any request is made
    """
    problems = []
    allowed = set(operation.required) | set(operation.optional)
    for name in sorted(set(params) - allowed):
        problems.append('Unknown parameter in input: "{}", must be one of: {}'.format(name, ", ".join(sorted(allowed))))
    for name in operation.required:
        if name not in params:
            problems.append('Missing required parameter in input: "{}"'.format(name))

    body = {}
    for name, value in params.items():
        if name in operation.input_blobs:
            if isinstance(value, str):
                value = value.encode("utf-8")
            if not isinstance(value, (bytes, bytearray)):
                problems.append("Invalid type for parameter {}, value: <redacted>, type: {}".format(name, type(value)))
                continue
            value = base64.b64encode(bytes(value)).decode("ascii")
        body[name] = value

    if problems:
        raise botocore.exceptions.ParamValidationError(report="\n".join(problems))
    return body
