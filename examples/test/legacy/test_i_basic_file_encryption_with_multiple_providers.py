# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the Bytes Streams Multiple Providers examples in the AWS-hosted documentation."""
import os
import tempfile

import botocore.session
import pytest

from ...src.legacy.basic_file_encryption_with_multiple_providers import cycle_file
from .examples_test_utils import get_cmk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_cycle_file():
    cmk_arn = get_cmk_arn()
    handle, filename = tempfile.mkstemp()
    with open(filename, "wb") as f:
        f.write(static_plaintext)
    try:
        new_files = cycle_file(
            key_arn=cmk_arn, source_plaintext_filename=filename, botocore_session=botocore.session.Session()
        )
        for f in new_files:
            os.remove(f)
    finally:
        os.close(handle)
        os.remove(filename)
