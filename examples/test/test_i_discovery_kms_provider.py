# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for the encryption and decryption using one KMS CMK example."""

import botocore.session
import pytest

from ..src.discovery_kms_provider import encrypt_decrypt
from .examples_test_utils import get_cmk_arn
from .examples_test_utils import static_plaintext


pytestmark = [pytest.mark.examples]


def test_discovery_kms_provider():
    plaintext = static_plaintext
    cmk_arn = get_cmk_arn()
    encrypt_decrypt(key_arn=cmk_arn, source_plaintext=plaintext, botocore_session=botocore.session.Session())
