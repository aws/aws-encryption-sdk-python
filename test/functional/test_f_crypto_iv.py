# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for IV generation helper functions."""
import pytest

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.internal.crypto.iv import frame_iv, header_auth_iv, non_framed_body_iv
from aws_encryption_sdk.internal.defaults import ALGORITHM, MAX_FRAME_COUNT

pytestmark = [pytest.mark.functional, pytest.mark.local]

VALUES = {
    "ivs": {
        "header_auth": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "non_framed": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        "frame": [
            {"sequence_number": 1, "iv": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
            {"sequence_number": 10000, "iv": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\x10"},
            {
                "sequence_number": 4294967295,  # 2^32 - 1 :: max frame count
                "iv": b"\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
            },
        ],
    }
}


@pytest.mark.parametrize(
    "sequence_number, iv", [(entry["sequence_number"], entry["iv"]) for entry in VALUES["ivs"]["frame"]]
)
def test_framed_iv(sequence_number, iv):
    assert frame_iv(ALGORITHM, sequence_number) == iv


@pytest.mark.parametrize("sequence_number", (-1, 0, MAX_FRAME_COUNT + 1))
def test_framed_iv_invalid_sequence_numbers(sequence_number):
    with pytest.raises(ActionNotAllowedError) as excinfo:
        frame_iv(ALGORITHM, sequence_number)

    excinfo.match(r"Invalid frame sequence number: *")


def test_non_framed_body_iv():
    assert non_framed_body_iv(ALGORITHM) == VALUES["ivs"]["non_framed"]


def test_header_auth_iv():
    assert header_auth_iv(ALGORITHM) == VALUES["ivs"]["header_auth"]
