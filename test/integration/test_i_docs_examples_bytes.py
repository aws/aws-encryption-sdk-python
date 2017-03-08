"""Unit test suite for the Bytes Streams examples in the AWS-hosted documentation.

.. note::
    These tests rely on discoverable AWS credentials existing.
"""
import os
import tempfile

import pytest

from .test_i_aws_encrytion_sdk_client import skip_tests, SKIP_MESSAGE
from .docs_examples_bytes import cycle_file


@pytest.mark.skipif(skip_tests(), reason=SKIP_MESSAGE)
def test_cycle_file():
    _handle, filename = tempfile.mkstemp()
    with open(filename, 'wb') as f:
        f.write(os.urandom(1024))
    try:
        new_files = cycle_file(source_plaintext_filename=filename)
        for f in new_files:
            os.remove(f)
    finally:
        os.remove(filename)
