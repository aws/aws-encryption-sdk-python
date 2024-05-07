# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the encryption and decryption of streaming data using one KMS CMK example."""
import os
import tempfile

import botocore.session
import pytest

from ..src.one_kms_cmk_streaming_data import encrypt_decrypt_stream
from .examples_test_utils import get_cmk_arn, static_plaintext


pytestmark = [pytest.mark.examples]


def test_one_kms_cmk_streaming_data():
    cmk_arn = get_cmk_arn()
    handle, filename = tempfile.mkstemp()
    with open(filename, "wb") as f:
        f.write(static_plaintext)
    try:
        new_files = encrypt_decrypt_stream(
            key_arn=cmk_arn, source_plaintext_filename=filename, botocore_session=botocore.session.Session()
        )
        for f in new_files:
            os.remove(f)
    finally:
        os.close(handle)
        os.remove(filename)
