"""Unit test suite for the Bytes Streams Multiple Providers examples in the AWS-hosted documentation.

.. note::
    These tests rely on discoverable AWS credentials existing.
"""
import os
import tempfile

import pytest

from .test_i_aws_encrytion_sdk_client import (
    read_test_config, get_cmk_arn, setup_botocore_session, skip_tests, SKIP_MESSAGE
)
from .docs_examples_multiple_providers import cycle_file


@pytest.mark.skipif(skip_tests(), reason=SKIP_MESSAGE)
def test_cycle_file():
    config = read_test_config()
    cmk_arn = get_cmk_arn(config)
    botocore_session = setup_botocore_session(config)
    _handle, filename = tempfile.mkstemp()
    with open(filename, 'wb') as f:
        f.write(os.urandom(1024))
    try:
        new_files = cycle_file(
            key_arn=cmk_arn,
            source_plaintext_filename=filename,
            botocore_session=botocore_session
        )
        for f in new_files:
            os.remove(f)
    finally:
        os.remove(filename)
