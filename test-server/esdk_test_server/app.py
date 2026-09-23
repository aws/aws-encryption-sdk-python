# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The hand-implemented rpcv2Cbor HTTP server for the Python Language_Server.

Implements the wire contract of the single Smithy model by hand (no generated
code): routes ``POST /service/ESDKTestServer/operation/<Op>`` requests, decodes
the CBOR request body, dispatches to the operation handler, and encodes the CBOR
response. Every operation's outcome is exactly one of a modeled success response,
a ``GenericServerError``, or an ``ESDKClientError`` — the latter two serialized as
a CBOR map carrying the ``__type`` discriminator (the error's absolute shape id)
so the stock generated Java Test_Client maps them back to the correct modeled
type (Requirements 5.1-5.6, 6.1-6.4), matching the Java server's DiscriminatingCbor.
"""

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import cbor2

from .esdk_bridge import ClientError, ServerError, build_client

_NAMESPACE = "aws.cryptography.esdk.testserver"
_GENERIC_SERVER_ERROR = _NAMESPACE + "#GenericServerError"
_ESDK_CLIENT_ERROR = _NAMESPACE + "#ESDKClientError"
_SMITHY_PROTOCOL = "rpc-v2-cbor"
_CBOR_CONTENT_TYPE = "application/cbor"


class ClientRegistry:
    """Thread-safe in-memory ClientId -> EsdkClientBundle registry (Requirement 3)."""

    def __init__(self):
        self._clients = {}
        self._lock = threading.Lock()

    def register(self, bundle):
        client_id = str(uuid.uuid4())
        with self._lock:
            self._clients[client_id] = bundle
        return client_id

    def resolve(self, client_id):
        with self._lock:
            return self._clients.get(client_id)


def _require_client(registry, request):
    """Resolve the referenced client or reject with a GenericServerError (Req 3.9)."""
    client_id = request.get("clientId")
    if not client_id:
        raise ServerError("clientId is required and must be non-empty")
    bundle = registry.resolve(client_id)
    if bundle is None:
        raise ServerError(f"no client registered for clientId: {client_id}")
    return bundle


# ---------------------------------------------------------------------------
# Operation handlers. Each returns the response member map or raises
# ClientError (-> ESDKClientError) / ServerError (-> GenericServerError).
# ---------------------------------------------------------------------------
def _describe_exception(exc):
    """Flatten an exception to a message, appending any nested ``list`` of
    encountered exceptions (the MPL ``CollectionOfErrors`` raised when e.g. no
    configured key could decrypt) so the underlying causes are visible rather
    than only the top-level "the list ... is available via `list`"."""
    message = str(exc)
    nested = getattr(exc, "list", None)
    if isinstance(nested, (list, tuple)) and nested:
        causes = "; ".join(_describe_exception(cause) for cause in nested)
        message = f"{message} [encountered: {causes}]"
    return message


def _create_client(registry, request):
    config = request.get("config")
    if config is None:
        raise ServerError("config is required")
    try:
        bundle = build_client(config)
    except (ClientError, ServerError):
        raise
    except Exception as exc:  # noqa: BLE001 - construction failure -> GenericServerError (Req 3.6)
        raise ServerError(f"CreateClient failed to construct the ESDK client: {_describe_exception(exc)}") from exc
    return {"clientId": registry.register(bundle)}


def _encrypt(registry, request):
    bundle = _require_client(registry, request)
    try:
        ciphertext = bundle.encrypt(
            request["plaintext"],
            request.get("encryptionContext"),
            request.get("algorithmSuiteId"),
            request.get("frameLength"),
        )
    except Exception as exc:  # noqa: BLE001 - ESDK-thrown -> ESDKClientError (Req 4.10, 5.6)
        raise ClientError(_describe_exception(exc)) from exc
    return {"ciphertext": ciphertext}


def _decrypt(registry, request):
    bundle = _require_client(registry, request)
    try:
        plaintext, encryption_context, algorithm_suite_id = bundle.decrypt(
            request["ciphertext"], request.get("encryptionContext"))
    except Exception as exc:  # noqa: BLE001
        raise ClientError(_describe_exception(exc)) from exc
    response = {"plaintext": plaintext}
    if encryption_context:
        response["encryptionContext"] = encryption_context
    if algorithm_suite_id:
        response["algorithmSuiteId"] = algorithm_suite_id
    return response


def _encrypt_stream(registry, request):
    bundle = _require_client(registry, request)
    try:
        ciphertext = bundle.encrypt_stream(
            request["plaintext"],
            request.get("encryptionContext"),
            request.get("algorithmSuiteId"),
            request.get("frameLength"),
            request.get("plaintextLengthBound"),
        )
    except Exception as exc:  # noqa: BLE001
        raise ClientError(_describe_exception(exc)) from exc
    return {"ciphertext": ciphertext}


def _decrypt_stream(registry, request):
    bundle = _require_client(registry, request)
    try:
        plaintext, encryption_context, algorithm_suite_id = bundle.decrypt_stream(
            request["ciphertext"], request.get("encryptionContext"))
    except Exception as exc:  # noqa: BLE001
        raise ClientError(_describe_exception(exc)) from exc
    response = {"plaintext": plaintext}
    if encryption_context:
        response["encryptionContext"] = encryption_context
    if algorithm_suite_id:
        response["algorithmSuiteId"] = algorithm_suite_id
    return response


_OPERATIONS = {
    "CreateClient": _create_client,
    "Encrypt": _encrypt,
    "Decrypt": _decrypt,
    "EncryptStream": _encrypt_stream,
    "DecryptStream": _decrypt_stream,
}


def _make_handler(registry):
    class RpcV2CborHandler(BaseHTTPRequestHandler):
        # Speak HTTP/1.1 with keep-alive so the smithy-java client's pooled
        # connections stay valid across the many requests the Tests make. Every
        # response carries a Content-Length (see _send_cbor), which is what lets
        # the base handler keep the connection open rather than closing it after
        # each response (the HTTP/1.0 default, which caused intermittent
        # "received no bytes" transport errors on reused connections).
        protocol_version = "HTTP/1.1"

        # Quiet the default per-request stderr logging.
        def log_message(self, *args):  # noqa: D401
            pass

        def _send_cbor(self, status, payload):
            body = cbor2.dumps(payload)
            self.send_response(status)
            self.send_header("smithy-protocol", _SMITHY_PROTOCOL)
            self.send_header("Content-Type", _CBOR_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_error(self, type_id, message):
            # Modeled @error("client") shapes: HTTP 400 with a CBOR body carrying
            # the __type discriminator so the client picks the right modeled error.
            self._send_cbor(400, {"__type": type_id, "message": message})

        def do_POST(self):  # noqa: N802 - required name
            operation = self.path.rsplit("/", 1)[-1] if "/operation/" in self.path else None
            handler = _OPERATIONS.get(operation)
            if handler is None:
                self._send_error(_GENERIC_SERVER_ERROR, f"unknown operation: {self.path}")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                request = cbor2.loads(raw) if raw else {}
                response = handler(registry, request)
                self._send_cbor(200, response)
            except ClientError as exc:
                self._send_error(_ESDK_CLIENT_ERROR, str(exc))
            except ServerError as exc:
                self._send_error(_GENERIC_SERVER_ERROR, str(exc))
            except Exception as exc:  # noqa: BLE001 - never leak a bare HTTP error (Req 6.1-6.4)
                self._send_error(_GENERIC_SERVER_ERROR, f"unexpected server error: {exc}")

    return RpcV2CborHandler


class _EsdkTestThreadingHTTPServer(ThreadingHTTPServer):
    # A generous listen backlog so bursts of new connections from the
    # heavily-parameterized Tests are not reset (the socketserver default of 5 is
    # far too small and manifested as intermittent "received no bytes" errors).
    request_queue_size = 128
    # Do not let a lingering worker thread block process shutdown.
    daemon_threads = True
    # Free the port immediately on restart.
    allow_reuse_address = True


def serve(port, host="127.0.0.1"):
    """Start the Python Language_Server on ``host:port`` and serve until stopped."""
    registry = ClientRegistry()
    server = _EsdkTestThreadingHTTPServer((host, port), _make_handler(registry))
    print(f"esdk-test-server (python) listening at http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
