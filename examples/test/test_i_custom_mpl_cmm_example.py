# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for encryption and decryption using custom CMM."""
import boto3
import pytest
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring

from ..src.custom_mpl_cmm_example import MPLCustomSigningSuiteOnlyCMM, encrypt_decrypt_with_cmm

pytestmark = [pytest.mark.examples]


def test_custom_cmm_example():
    """Test method for encryption and decryption using V3 default CMM."""
    kms_key_id = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"

    # Create KMS keyring to use with the CMM
    kms_client = boto3.client('kms', region_name="us-west-2")

    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=kms_key_id,
        kms_client=kms_client
    )

    kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=keyring_input
    )

    # Create the custom MPL signing CMM using the keyring
    cmm = MPLCustomSigningSuiteOnlyCMM(keyring=kms_keyring)

    encrypt_decrypt_with_cmm(cmm=cmm)
