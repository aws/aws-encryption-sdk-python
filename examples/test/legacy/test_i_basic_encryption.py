# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the Strings examples in the AWS-hosted documentation."""
import botocore.session
import pytest

from ...src.legacy.basic_encryption import cycle_string
from .examples_test_utils import get_cmk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_cycle_string():
    plaintext = static_plaintext
    cmk_arn = get_cmk_arn()
    cycle_string(key_arn=cmk_arn, source_plaintext=plaintext, botocore_session=botocore.session.Session())
