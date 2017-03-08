"""Unit test suite for the Strings examples in the AWS-hosted documentation.

.. note::
    These tests rely on discoverable AWS credentials existing.
"""
import os

import pytest

from .test_i_aws_encrytion_sdk_client import (
    read_test_config, get_cmk_arn, setup_botocore_session, skip_tests, SKIP_MESSAGE
)
from .docs_examples_strings import cycle_string


@pytest.mark.skipif(skip_tests(), reason=SKIP_MESSAGE)
def test_cycle_string():
    plaintext = os.urandom(1024)
    config = read_test_config()
    cmk_arn = get_cmk_arn(config)
    botocore_session = setup_botocore_session(config)
    cycle_string(
        key_arn=cmk_arn,
        source_plaintext=plaintext,
        botocore_session=botocore_session
    )
