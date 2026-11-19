# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the multi-tenant AWS KMS keyring example."""
import botocore.session
import pytest

from ..src.multi_tenant_kms_keyring_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt using a TenantKmsClient per tenant."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    # The test environment has one identity; real tenants would each have their own credentials.
    credentials = botocore.session.Session().get_credentials()
    encrypt_and_decrypt_with_keyring(
        tenant_kms_key_ids={"TenantA": kms_key_id, "TenantB": kms_key_id},
        tenant_credentials={"TenantA": credentials, "TenantB": credentials},
    )
