# ESDK TestServer — Python Language_Server (hand-implemented)

A hand-implemented `Language_Server` for the ESDK TestServer. Smithy server
codegen is not used for Python, so this server hand-writes the marshalling layer
that conforms to the single Smithy model's **rpcv2Cbor** wire contract
(Requirement 1.8) and delegates to the real **AWS Encryption SDK for Python**.

## What it implements

- The five operations `CreateClient`, `Encrypt`, `Decrypt`, `EncryptStream`,
  `DecryptStream`, routed at `POST /service/ESDKTestServer/operation/<Op>`.
- A thread-safe `ClientId -> client` registry (`CreateClient` returns a UUID).
- The tagged-union-via-optional-members config (keyrings, CMMs, recursive
  multi-keyring / required-EC CMM) → real Material Providers Library keyrings and
  cryptographic materials managers, mirroring the Java server's `EsdkClientFactory`.
- The two modeled errors serialized as a CBOR map carrying the `__type`
  discriminator (the error's absolute shape id), so the stock generated Java
  `Test_Client` maps them back to `GenericServerError` / `ESDKClientError`
  (matching the Java server's `DiscriminatingCbor`).
- Streaming: the `*Stream` operations carry a plain blob on the wire and drive the
  ESDK streaming API server-side (Streaming_Capable).

## Dependencies

- `cbor2`, `boto3` (declared in `pyproject.toml`).
- The **AWS Encryption SDK for Python** + **Material Providers Library**, installed
  from a clone of https://github.com/aws/aws-encryption-sdk-python (its repo URL is
  part of the Configuration). The orchestrator/Makefile clones it and installs it
  editable from the relative path, so the server runs against live source with no
  compile step.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -e .deps/aws-encryption-sdk-python \
    'aws-cryptographic-material-providers>=1.7.4,<=1.11.2' cbor2 boto3
.venv/bin/pip install -e .
.venv/bin/python -m esdk_test_server 8091   # listens on http://127.0.0.1:8091
```

Point the Tests at it (alongside the Java server) via runtime configuration:

```
-Desdk.testserver.targets=java:3=http://127.0.0.1:8080,python:4=http://127.0.0.1:8091
```
