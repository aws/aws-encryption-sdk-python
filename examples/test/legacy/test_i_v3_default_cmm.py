# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for encryption and decryption using custom CMM."""

import botocore.session
import pytest

import aws_encryption_sdk
from ...src.legacy.custom_cmm_example import encrypt_decrypt_with_cmm, CustomSigningSuiteOnlyCMM
from .v3_default_cmm import V3DefaultCryptoMaterialsManager
from .examples_test_utils import get_cmk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_custom_cmm_example():
    """Test method for encryption and decryption using V3 default CMM."""
    plaintext = static_plaintext
    cmk_arn = get_cmk_arn()
    botocore_session = botocore.session.Session()

    # Create a KMS master key provider.
    kms_kwargs = dict(key_ids=[cmk_arn])
    if botocore_session is not None:
        kms_kwargs["botocore_session"] = botocore_session
    master_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)

    # Create the V3 default CMM (V3DefaultCryptoMaterialsManager) using the master_key_provider
    cmm = CustomSigningSuiteOnlyCMM(master_key_provider=master_key_provider)

    encrypt_decrypt_with_cmm(cmm=cmm,
                             source_plaintext=plaintext)


def test_v3_default_cmm():
    """Test method for encryption and decryption using V3 default CMM."""
    plaintext = static_plaintext
    cmk_arn = get_cmk_arn()
    botocore_session = botocore.session.Session()

    # Create a KMS master key provider.
    kms_kwargs = dict(key_ids=[cmk_arn])
    if botocore_session is not None:
        kms_kwargs["botocore_session"] = botocore_session
    master_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)

    # Create the V3 default CMM (V3DefaultCryptoMaterialsManager) using the master_key_provider
    cmm = V3DefaultCryptoMaterialsManager(master_key_provider=master_key_provider)

    encrypt_decrypt_with_cmm(cmm=cmm,
                             source_plaintext=plaintext)
