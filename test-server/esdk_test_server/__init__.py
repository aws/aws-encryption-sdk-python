# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Hand-implemented Python Language_Server for the ESDK TestServer.

Speaks the same rpcv2Cbor wire contract as the single Smithy model (the source of
truth) and delegates to the real AWS Encryption SDK for Python. There is no
generated code here: the marshalling layer is hand-written to conform to the
model's request/response shapes, the five operations, and the two modeled errors
(Requirement 1.8).
"""
