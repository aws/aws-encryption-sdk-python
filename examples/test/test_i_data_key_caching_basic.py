# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit test suite for the basic data key caching example in the AWS-hosted documentation."""
import os
import sys
sys.path.extend([  # noqa
    os.sep.join([os.path.dirname(__file__), '..', '..', 'test', 'integration']),
    os.sep.join([os.path.dirname(__file__), '..', 'src'])
])

import pytest

from data_key_caching_basic import encrypt_with_caching
from integration_test_utils import get_cmk_arn

pytestmark = [pytest.mark.examples]


def test_encrypt_with_caching():
    cmk_arn = get_cmk_arn()
    encrypt_with_caching(
        kms_cmk_arn=cmk_arn,
        max_age_in_cache=10.0,
        cache_capacity=10
    )
