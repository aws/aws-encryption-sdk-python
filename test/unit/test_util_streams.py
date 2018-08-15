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

import pytest

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.internal.utils.streams import ROStream, TeeStream

pytestmark = [pytest.mark.unit, pytest.mark.local]


def data():
    return io.BytesIO(b"asdijfhoaisjdfoiasjdfoijawef")


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
