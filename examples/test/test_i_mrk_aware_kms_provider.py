# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit test suite for the encryption and decryption using one KMS CMK example."""

import pytest

from ..src.mrk_aware_kms_provider import encrypt_decrypt
from .examples_test_utils import get_mrk_arn, get_second_mrk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_discovery_kms_provider():
    plaintext = static_plaintext
    cmk_arn_1 = get_mrk_arn()
    cmk_arn_2 = get_second_mrk_arn()
    encrypt_decrypt(mrk_arn=cmk_arn_1, mrk_arn_second_region=cmk_arn_2, source_plaintext=plaintext)
