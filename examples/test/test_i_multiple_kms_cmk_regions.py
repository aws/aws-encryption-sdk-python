# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit test suite for the encryption and decryption using multiple KMS CMKs in multiple regions example."""

import botocore.session
import pytest

from ..src.multiple_kms_cmk_regions import multiple_kms_cmk_regions

from .examples_test_utils import get_cmk_arn
from .examples_test_utils import static_plaintext


pytestmark = [pytest.mark.examples]


def test_multiple_kms_cmk_regions():
    plaintext = static_plaintext
    cmk_arn_1 = get_cmk_arn("us-west-2")
    cmk_arn_2 = get_cmk_arn("eu-central-1")
    multiple_kms_cmk_regions(
        cmk_arn_1, cmk_arn_2, source_plaintext=plaintext, botocore_session=botocore.session.Session()
    )
