# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the Bytes Streams examples in the AWS-hosted documentation."""
import os
import tempfile

import pytest

from ...src.legacy.basic_file_encryption_with_raw_key_provider import cycle_file
from .examples_test_utils import static_plaintext

pytestmark = [pytest.mark.examples]


def test_cycle_file():
    handle, filename = tempfile.mkstemp()
    with open(filename, "wb") as f:
        f.write(static_plaintext)
    try:
        new_files = cycle_file(source_plaintext_filename=filename)
        for f in new_files:
            os.remove(f)
    finally:
        os.close(handle)
        os.remove(filename)
