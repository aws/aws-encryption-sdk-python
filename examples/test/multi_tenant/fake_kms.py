# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""An in-memory AWS KMS, substituted for a ``KmsTransport``'s connection pool, for offline tests.

Each KMS key is authorized for exactly one access key,
so tests can assert that every request was signed with the right tenant's credentials.

This module MUST NOT import the MPL; the legacy Master Key Provider tests use it.
"""
import base64
import json
import os
import re

_CREDENTIAL_SCOPE = re.compile(r"Credential=([^/]+)/\d{8}/([^/]+)/kms/aws4_request")


class FakeResponse:  # pylint: disable=too-few-public-methods
    """The subset of ``urllib3.HTTPResponse`` that ``KmsTransport`` reads."""

    def __init__(self, status, body, headers=None):
        """Serialize ``body`` if it is a dict."""
        self.status = status
        self.data = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
        self.headers = dict({"x-amzn-RequestId": "fake-request-id"}, **(headers or {}))


class FakeKms:
    """Stands in for ``urllib3.PoolManager``; see ``install``."""

    def __init__(self):
        """Start with no keys, requests, or scripted responses."""
        #: KMS key ARN -> the only access key allowed to use it
        self.key_owners = {}
        #: Every request: dict(operation, access_key, region, url, user_agent, body)
        self.requests = []
        #: Responses (or exceptions) to return, in order, before behaving like KMS
        self.scripted = []

    def add_key(self, key_arn, access_key):
        """Authorize ``access_key``, and only ``access_key``, to use ``key_arn``."""
        self.key_owners[key_arn] = access_key

    def clear(self):
        """Do nothing, as ``PoolManager.clear`` would for an idle pool."""

    def urlopen(self, method, url, body=None, headers=None, **kwargs):  # pylint: disable=unused-argument
        """Record the request, then return a scripted response or behave like KMS (``PoolManager.urlopen``)."""
        headers = {key: value.decode("utf-8") if isinstance(value, bytes) else value for key, value in headers.items()}
        match = _CREDENTIAL_SCOPE.search(headers.get("Authorization", ""))
        operation = headers["X-Amz-Target"].split(".", 1)[1]
        request = json.loads(body.decode("utf-8"))
        self.requests.append(
            {
                "operation": operation,
                "access_key": match.group(1) if match else None,
                "region": match.group(2) if match else None,
                "url": url,
                "user_agent": headers.get("User-Agent"),
                "body": request,
            }
        )
        if self.scripted:
            scripted = self.scripted.pop(0)
            if isinstance(scripted, Exception):
                raise scripted
            return scripted
        if method != "POST" or match is None:
            return _error(403, "IncompleteSignatureException", "Missing SigV4 credential scope")
        return getattr(self, "_" + operation)(request, match.group(1))

    # KMS operations. A ciphertext is the JSON of its key, encryption context, and plaintext.

    def _authorize(self, key_arn, access_key):
        if key_arn not in self.key_owners:
            return _error(400, "NotFoundException", "Key '{}' does not exist".format(key_arn))
        if self.key_owners[key_arn] != access_key:
            return _error(400, "AccessDeniedException", "{} is not authorized to use {}".format(access_key, key_arn))
        return None

    @staticmethod
    def _seal(key_arn, encryption_context, plaintext):
        envelope = {"KeyId": key_arn, "EncryptionContext": encryption_context or {}, "Plaintext": plaintext}
        return base64.b64encode(json.dumps(envelope, sort_keys=True).encode("utf-8")).decode("ascii")

    def _open(self, ciphertext_b64, encryption_context, access_key, expected_key_id=None):
        try:
            envelope = json.loads(base64.b64decode(ciphertext_b64).decode("utf-8"))
        except ValueError:
            return None, _error(400, "InvalidCiphertextException", "")
        if expected_key_id is not None and _replica_id(expected_key_id) != _replica_id(envelope["KeyId"]):
            return None, _error(400, "IncorrectKeyException", "")
        # A multi-Region key's replica decrypts its ciphertext; authorize the replica that was asked for.
        denied = self._authorize(expected_key_id or envelope["KeyId"], access_key)
        if denied is not None:
            return None, denied
        if envelope["EncryptionContext"] != (encryption_context or {}):
            return None, _error(400, "InvalidCiphertextException", "")
        return envelope, None

    def _GenerateDataKey(self, request, access_key, include_plaintext=True):  # pylint: disable=invalid-name
        denied = self._authorize(request["KeyId"], access_key)
        if denied is not None:
            return denied
        length = request.get("NumberOfBytes") or {"AES_128": 16, "AES_256": 32}[request.get("KeySpec", "AES_256")]
        plaintext = base64.b64encode(os.urandom(length)).decode("ascii")
        response = {
            "KeyId": request["KeyId"],
            "CiphertextBlob": self._seal(request["KeyId"], request.get("EncryptionContext"), plaintext),
        }
        if include_plaintext:
            response["Plaintext"] = plaintext
        return FakeResponse(200, response)

    def _GenerateDataKeyWithoutPlaintext(self, request, access_key):  # pylint: disable=invalid-name
        return self._GenerateDataKey(request, access_key, include_plaintext=False)

    def _Encrypt(self, request, access_key):  # pylint: disable=invalid-name
        denied = self._authorize(request["KeyId"], access_key)
        if denied is not None:
            return denied
        return FakeResponse(
            200,
            {
                "KeyId": request["KeyId"],
                "CiphertextBlob": self._seal(request["KeyId"], request.get("EncryptionContext"), request["Plaintext"]),
            },
        )

    def _Decrypt(self, request, access_key):  # pylint: disable=invalid-name
        envelope, error = self._open(
            request["CiphertextBlob"], request.get("EncryptionContext"), access_key, request.get("KeyId")
        )
        if error is not None:
            return error
        key_id = request.get("KeyId") or envelope["KeyId"]
        return FakeResponse(200, {"KeyId": key_id, "Plaintext": envelope["Plaintext"]})

    def _ReEncrypt(self, request, access_key):  # pylint: disable=invalid-name
        envelope, error = self._open(
            request["CiphertextBlob"], request.get("SourceEncryptionContext"), access_key, request.get("SourceKeyId")
        )
        if error is not None:
            return error
        denied = self._authorize(request["DestinationKeyId"], access_key)
        if denied is not None:
            return denied
        return FakeResponse(
            200,
            {
                "SourceKeyId": envelope["KeyId"],
                "KeyId": request["DestinationKeyId"],
                "CiphertextBlob": self._seal(
                    request["DestinationKeyId"], request.get("DestinationEncryptionContext"), envelope["Plaintext"]
                ),
            },
        )


def _replica_id(key_arn):
    """Return an ARN that is the same for every replica of a multi-Region key."""
    parts = key_arn.split(":")
    if len(parts) == 6 and parts[5].startswith("key/mrk-"):
        parts[3] = "*"
    return ":".join(parts)


def _error(status, code, message):
    return FakeResponse(status, {"__type": "com.amazonaws.kms#" + code, "message": message})


def install(transport):
    """Replace ``transport``'s connection pool with a ``FakeKms``, and disables backoff sleeps.

    :rtype: FakeKms
    """
    fake = FakeKms()
    transport._pool = fake  # pylint: disable=protected-access
    transport._backoff = lambda attempt: None  # pylint: disable=protected-access
    return fake
