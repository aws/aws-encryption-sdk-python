# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test suite for the multi-tenant KMS Master Key Providers example."""
import botocore.session
import pytest

from ...src.legacy.multi_tenant_kms_master_key_provider import encrypt_decrypt
from .examples_test_utils import get_cmk_arn, get_second_cmk_arn, static_plaintext

pytestmark = [pytest.mark.examples]


def test_multi_tenant_kms_master_key_provider():
    session = botocore.session.Session()
    # The test environment has one identity; real tenants would each have their own credentials.
    credentials = session.get_credentials()
    encrypt_decrypt(
        tenant_key_arns={"TenantA": get_cmk_arn(), "TenantB": get_second_cmk_arn()},
        tenant_credentials={"TenantA": credentials, "TenantB": credentials},
        source_plaintext=static_plaintext,
        botocore_session=session,
    )
