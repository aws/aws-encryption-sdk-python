# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for encryption and decryption using V3 defualt CMM."""

import botocore.session
import pytest

from ...src.legacy.v3_default_cmm import encrypt_decrypt_with_v3_default_cmm
from .examples_test_utils import get_cmk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_v3_default_cmm():
    """Test method for encryption and decryption using V3 defualt CMM."""
    plaintext = static_plaintext
    cmk_arn = get_cmk_arn()
    encrypt_decrypt_with_v3_default_cmm(key_arn=cmk_arn,
                                        source_plaintext=plaintext,
                                        botocore_session=botocore.session.Session())
