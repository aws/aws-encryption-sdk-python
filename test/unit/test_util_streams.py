# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.internal.utils.streams"""
import io

import pytest

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.internal.str_ops import to_bytes, to_str
from aws_encryption_sdk.internal.utils.streams import InsistentReaderBytesIO, ROStream, TeeStream

from .unit_test_utils import ExactlyTwoReads, NothingButRead, SometimesIncompleteReaderIO

pytestmark = [pytest.mark.unit, pytest.mark.local]


def data(length=None, stream_type=io.BytesIO, converter=to_bytes):
    source = b"asdijfhoaisjdfoiasjdfoijawef"
    chunk_length = 100

    if length is None:
        length = len(source)

    while len(source) < length:
        source += source[:chunk_length]

    return stream_type(converter(source[:length]))


def test_rostream():
    test = ROStream(data())

    with pytest.raises(ActionNotAllowedError) as excinfo:
        test.write(b"")

    excinfo.match(r"Write not allowed on ROStream objects")


def test_teestream_full():
    new_tee = io.BytesIO()
    test_tee = TeeStream(data(), new_tee)

    raw_read = test_tee.read()

    assert data().getvalue() == raw_read == new_tee.getvalue()


@pytest.mark.parametrize(
    "stream_type, converter",
    (
        (io.BytesIO, to_bytes),
        (SometimesIncompleteReaderIO, to_bytes),
        (io.StringIO, to_str),
        (NothingButRead, to_bytes),
    ),
)
@pytest.mark.parametrize("bytes_to_read", range(1, 102))
@pytest.mark.parametrize("source_length", (1, 11, 100))
def test_insistent_stream(source_length, bytes_to_read, stream_type, converter):
    source = InsistentReaderBytesIO(data(length=source_length, stream_type=stream_type, converter=converter))

    test = source.read(bytes_to_read)

    assert (source_length >= bytes_to_read and len(test) == bytes_to_read) or (
        source_length < bytes_to_read and len(test) == source_length
    )


def test_insistent_stream_close_partway_through():
    raw = data(length=100)
    source = ExactlyTwoReads(raw.getvalue())

    wrapped = InsistentReaderBytesIO(source)

    test = b""
    test += wrapped.read(10)  # actually reads 10 bytes
    test += wrapped.read(10)  # reads 5 bytes, stream is closed before third read can complete, truncating the result

    assert test == raw.getvalue()[:15]
