# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import random
import secrets
import string

import boto3
from aws_cryptographic_materialproviders.keystore import KeyStore
from aws_cryptographic_materialproviders.keystore.config import KeyStoreConfig
from aws_cryptographic_materialproviders.keystore.models import KMSConfigurationKmsKeyArn
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    AesWrappingAlg,
    CacheTypeDefault,
    CreateAwsKmsHierarchicalKeyringInput,
    CreateAwsKmsKeyringInput,
    CreateMultiKeyringInput,
    CreateRawAesKeyringInput,
    CreateRawRsaKeyringInput,
    DefaultCache,
    PaddingScheme,
)
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# MPL client. Used to create keyrings.
mpl_client: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
    config=MaterialProvidersConfig()
)


class TestKeyringCreator:

    # Private raw AES keyring creator.
    # Lifted from raw AES keyring example.
    @staticmethod
    def _create_raw_aes_keyring():
        static_key = secrets.token_bytes(32)

        keyring_input: CreateRawAesKeyringInput = CreateRawAesKeyringInput(
            key_namespace="some_key_namespace",
            key_name="some_key_name",
            wrapping_key=static_key,
            wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
        )

        raw_aes_keyring: IKeyring = mpl_client.create_raw_aes_keyring(
            input=keyring_input
        )

        return raw_aes_keyring

    # Private raw RSA keyring creator.
    # Lifted from raw RSA keyring example.
    @staticmethod
    def _create_raw_rsa_keyring():
        ssh_rsa_exponent = 65537
        bit_strength = 4096
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=ssh_rsa_exponent,
            key_size=bit_strength
        )

        public_key = key.public_key().public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key = key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption()
        )

        key_name_space = "some_key_name_space"
        key_name = "some_key_name"

        keyring_input: CreateRawRsaKeyringInput = CreateRawRsaKeyringInput(
            key_namespace=key_name_space,
            key_name=key_name,
            padding_scheme=PaddingScheme.OAEP_SHA256_MGF1,
            public_key=public_key,
            private_key=private_key
        )

        raw_rsa_keyring: IKeyring = mpl_client.create_raw_rsa_keyring(
            input=keyring_input
        )

        return raw_rsa_keyring

    # Private KMS keyring creator.
    # Lifted KMS keyring example.
    @staticmethod
    def _create_kms_keyring():
        kms_client = boto3.client('kms', region_name="us-west-2")
        keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
            kms_key_id="arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
            kms_client=kms_client
        )

        kms_keyring: IKeyring = mpl_client.create_aws_kms_keyring(
            input=keyring_input
        )

        return kms_keyring

    # Private hierarchical keyring creator.
    # Lifted hierarchical keyring example.
    @staticmethod
    def _create_hierarchical_keyring():
        kms_client = boto3.client('kms', region_name="us-west-2")
        ddb_client = boto3.client('dynamodb', region_name="us-west-2")

        keystore: KeyStore = KeyStore(
            config=KeyStoreConfig(
                ddb_client=ddb_client,
                ddb_table_name="KeyStoreDdbTable",
                logical_key_store_name="KeyStoreDdbTable",
                kms_client=kms_client,
                kms_configuration=KMSConfigurationKmsKeyArn(
                    value='arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
                ),
            )
        )

        keyring_input: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
            key_store=keystore,
            branch_key_id='a52dfaad-7dbd-4430-a1fd-abaa5299da07',
            ttl_seconds=600,
            cache=CacheTypeDefault(
                value=DefaultCache(
                    entry_capacity=100
                )
            ),
        )

        hierarchical_keyring: IKeyring = mpl_client.create_aws_kms_hierarchical_keyring(
            input=keyring_input
        )

        return hierarchical_keyring

    # Private multi-keyring creator.
    @staticmethod
    def _create_multi_keyring(keyrings):
        a = mpl_client.create_multi_keyring(CreateMultiKeyringInput(
            generator=keyrings[0],
            child_keyrings=keyrings[1:]
        ))
        return a


class TestEncryptionContexts:

    # Encryption contexts under test
    SOME_EMPTY_ENCRYPTION_CONTEXT = {}
    SOME_SINGLE_ITEM_ENCRYPTION_CONTEXT = {"some_key": "some_value"}
    SOME_DOUBLE_ITEM_ENCRYPTION_CONTEXT = {"some_key": "some_value", "some_other_key": "some_other_value"}
    SOME_MANY_ITEM_ENCRYPTION_CONTEXT = {
        ''.join(random.choices(string.ascii_letters, k=6))
        : ''.join(random.choices(string.ascii_letters, k=6)) for _ in range(20)
    }
    ALL_ENCRYPTION_CONTEXTS = [
        SOME_EMPTY_ENCRYPTION_CONTEXT,
        SOME_SINGLE_ITEM_ENCRYPTION_CONTEXT,
        SOME_DOUBLE_ITEM_ENCRYPTION_CONTEXT,
        SOME_MANY_ITEM_ENCRYPTION_CONTEXT,
    ]

    NONEMPTY_ENCRYPTION_CONTEXTS = [
        SOME_SINGLE_ITEM_ENCRYPTION_CONTEXT,
        SOME_DOUBLE_ITEM_ENCRYPTION_CONTEXT,
        SOME_MANY_ITEM_ENCRYPTION_CONTEXT,
    ]

    AT_LEAST_TWO_ITEMS_ENCRYPTION_CONTEXTS = [
        SOME_DOUBLE_ITEM_ENCRYPTION_CONTEXT,
        SOME_MANY_ITEM_ENCRYPTION_CONTEXT,
    ]
