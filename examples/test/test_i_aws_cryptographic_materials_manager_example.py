# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the AWS Cryptographic Materials Manager example."""
import pytest

from ..src.aws_cryptographic_materials_manager_example import encrypt_and_decrypt_with_cmm

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_cmm():
    """Test function for encrypt and decrypt using the AWS Cryptographic Materials Manager example."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    encrypt_and_decrypt_with_cmm(kms_key_id)
