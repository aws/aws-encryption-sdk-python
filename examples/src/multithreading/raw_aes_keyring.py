# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This file contains methods to use for testing multi-threading for Raw AES keyring."""

import secrets

from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import AesWrappingAlg, CreateRawAesKeyringInput
from aws_cryptographic_material_providers.mpl.references import IKeyring


def create_keyring():
    """Demonstrate how to create a Raw AES keyring.

    Usage: create_keyring()
    """
    key_name_space = "Some managed raw keys"
    key_name = "My 256-bit AES wrapping key"

    static_key = secrets.token_bytes(32)

    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateRawAesKeyringInput = CreateRawAesKeyringInput(
        key_namespace=key_name_space,
        key_name=key_name,
        wrapping_key=static_key,
        wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
    )

    keyring: IKeyring = mat_prov.create_raw_aes_keyring(
        input=keyring_input
    )

    return keyring
