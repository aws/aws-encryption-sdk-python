# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the multi-tenant hierarchical keyring example."""
import botocore.session
import pytest

from ..src.multi_tenant_hierarchical_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using a Key Store and Hierarchical Keyring per tenant."""
    key_store_table_name = "KeyStoreDdbTable"
    kms_key_id = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
    # The test environment has one identity; real tenants would each have their own credentials.
    credentials = botocore.session.Session().get_credentials()
    encrypt_and_decrypt_with_keyring(
        key_store_table_name=key_store_table_name,
        logical_key_store_name=key_store_table_name,
        tenant_kms_key_ids={"TenantA": kms_key_id, "TenantB": kms_key_id},
        tenant_credentials={"TenantA": credentials, "TenantB": credentials},
    )
