# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Unit test suite for aws_encryption_sdk.internal.utils.streams"""
import io

from mock import sentinel
import pytest
from pytest_mock import mocker

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.internal.utils.streams import PassThroughStream, ROStream, TeeStream


def data():
    return io.BytesIO(b'asdijfhoaisjdfoiasjdfoijawef')


def test_passthrough_stream_init(mocker):
    mocker.patch.object(PassThroughStream, '_duplicate_api')
    test = PassThroughStream(sentinel.source_stream)

    assert test._source_stream is sentinel.source_stream
    test._duplicate_api.assert_called_once_with()


def test_passthrough_stream_duplicate_api():
    class _TestSource(object):
        z = sentinel.z
        x = sentinel.x
        _internal_unique = sentinel.internal_unique
    source = _TestSource()
    test = PassThroughStream(source)
    assert test.z is source.z
    assert test.x is source.x
    assert not hasattr(test, '_internal_unique')


def test_rostream():
    test = ROStream(data())

    with pytest.raises(ActionNotAllowedError) as excinfo:
        test.write(b'')

    excinfo.match(r'Write not allowed on ROStream objects')


def test_teestream_full():
    test_tee = TeeStream(data())

    raw_read = test_tee.read()
    tee_data = test_tee.tee.getvalue()

    assert data().getvalue() == raw_read == tee_data
