# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for empty serialized encryption contexts."""
import pytest

from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.internal.formatting.encryption_context import deserialize_encryption_context

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize("serialized_context", [b"\x00\x00", b"\x00\x00extra"])
def test_zero_entries(serialized_context):
    with pytest.raises(SerializationError):
        deserialize_encryption_context(serialized_context)


@pytest.mark.parametrize(
    "serialized_context, expected",
    [(b"", {}), (b"\x00\x01\x00\x01k\x00\x01v", {"k": "v"})],
)
def test_valid_context(serialized_context, expected):
    assert deserialize_encryption_context(serialized_context) == expected
