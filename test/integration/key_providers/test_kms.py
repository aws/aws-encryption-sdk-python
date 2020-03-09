# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for ``aws_encryption_sdk.key_provider.kms``."""
from test.integration.integration_test_utils import setup_kms_master_key_provider_with_botocore_session

import pytest
from botocore.exceptions import BotoCoreError

from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

pytestmark = [pytest.mark.integ]


def test_remove_bad_client():
    test = KMSMasterKeyProvider()
    fake_region = "us-fakey-12"
    test.add_regional_client(fake_region)

    with pytest.raises(BotoCoreError):
        test._regional_clients[fake_region].list_keys()

    assert fake_region not in test._regional_clients


def test_regional_client_does_not_modify_botocore_session(caplog):
    mkp = setup_kms_master_key_provider_with_botocore_session()
    fake_region = "us-fakey-12"

    assert mkp.config.botocore_session.get_config_variable("region") != fake_region
    mkp.add_regional_client(fake_region)
    assert mkp.config.botocore_session.get_config_variable("region") != fake_region
