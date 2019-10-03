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
"""Unit test suite for the encryption and decryption using one KMS CMK with an unsigned algorithm example."""

import botocore.session
import pytest

from ..src.one_kms_cmk_unsigned import encrypt_decrypt
from .examples_test_utils import get_cmk_arn
from .examples_test_utils import static_plaintext


pytestmark = [pytest.mark.examples]


def test_one_kms_cmk_unsigned():
    plaintext = static_plaintext
    cmk_arn = get_cmk_arn()
    encrypt_decrypt(key_arn=cmk_arn, source_plaintext=plaintext, botocore_session=botocore.session.Session())
