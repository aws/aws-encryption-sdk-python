# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit test suite for the Bytes Streams Multiple Providers examples in the AWS-hosted documentation."""
import os
import tempfile

import botocore.session
import pytest

from ..src.basic_file_encryption_with_multiple_providers import cycle_file
from .examples_test_utils import get_cmk_arn
from .examples_test_utils import static_plaintext


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
