# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the encryption and decryption using one KMS CMK example."""

import pytest

from ...src.legacy.mrk_aware_kms_provider import encrypt_decrypt
from .examples_test_utils import get_mrk_arn, get_second_mrk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_discovery_kms_provider():
    plaintext = static_plaintext
    cmk_arn_1 = get_mrk_arn()
    cmk_arn_2 = get_second_mrk_arn()
    encrypt_decrypt(mrk_arn=cmk_arn_1, mrk_arn_second_region=cmk_arn_2, source_plaintext=plaintext)
