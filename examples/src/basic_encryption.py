# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Example showing basic encryption and decryption of a value already in memory."""
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
import aws_cryptographic_materialproviders
import boto3

from aws_encryption_sdk.cmm_handler import (CMMHandler)

import sys

module_root_dir = '/'.join(__file__.split("/")[:-1])

sys.path.append(module_root_dir)

import aws_cryptographic_materialproviders

from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_materialproviders.client import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_materialproviders.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_materialproviders.models import (
    CreateAwsKmsHierarchicalKeyringInput,
    CacheTypeDefault,
    DefaultCache,
    GetBranchKeyIdInput,
    GetBranchKeyIdOutput,
    CreateDefaultCryptographicMaterialsManagerInput,
)
from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_materialproviders.references import (
    IKeyring,
    IBranchKeyIdSupplier,
)

from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_keystore.client import KeyStore
from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_keystore.config import KeyStoreConfig
from aws_cryptographic_materialproviders.smithygenerated.aws_cryptography_keystore.models import (
    CreateKeyInput,
    KMSConfigurationKmsKeyArn,
)

def cycle_string(key_arn, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under a KMS customer master key (CMK).

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient()

    # Create a KMS master key provider. Note that because we are planning on decrypting using this same provider,
    # we MUST provide the ARN of the KMS Key. If we provide a raw key id or a key alias, decryption will fail.
    kms_kwargs = dict(key_ids=[key_arn])
    if botocore_session is not None:
        kms_kwargs["botocore_session"] = botocore_session
    # master_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)

    #####
        

    key_store_table_name="KeyStoreDdbTable"
    logical_key_store_name="KeyStoreDdbTable"
    keystore_kms_key_id="arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"

    ddb_client = boto3.client('dynamodb')
    kms_client = boto3.client('kms')

    keystore: KeyStore = KeyStore(
        config=KeyStoreConfig(
            ddb_client=ddb_client,
            ddb_table_name=key_store_table_name,
            logical_key_store_name=logical_key_store_name,
            kms_client=kms_client,
            kms_configuration=KMSConfigurationKmsKeyArn(value=keystore_kms_key_id),
        )
    )

    new_branch_key_id: str = keystore.create_key(input=CreateKeyInput()).branch_key_identifier
    print(f"DEBUG: {new_branch_key_id=}")

    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateAwsKmsHierarchicalKeyringInput = CreateAwsKmsHierarchicalKeyringInput(
        key_store=keystore,
        branch_key_id=new_branch_key_id,
        ttl_seconds=600,
        cache=CacheTypeDefault(value=DefaultCache(entry_capacity=100)),
    )

    hierarchical_keyring: IKeyring = mat_prov.create_aws_kms_hierarchical_keyring(
        input=keyring_input
    )
    # This is as far as we can go in the linked Java example without the ESDK.
    # We can't use this keyring until it's integrated with the ESDK :(
    # Peek at it with print statement for now
    print(f"DEBUG: {hierarchical_keyring=}")

    #####

    cmm = mat_prov.create_default_cryptographic_materials_manager(CreateDefaultCryptographicMaterialsManagerInput(keyring=hierarchical_keyring))

    cmm_handler: CMMHandler = CMMHandler(cmm)

    # Encrypt the plaintext source data
    ciphertext, encryptor_header = client.encrypt(source=source_plaintext, materials_manager=cmm_handler)

    # Decrypt the ciphertext
    cycled_plaintext, decrypted_header = client.decrypt(source=ciphertext, materials_manager=cmm_handler)
    cycled_plaintext_str = str(cycled_plaintext, encoding="ascii")

    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source plaintext
    assert cycled_plaintext_str == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes all key pairs from
    # the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    #
    # In production, always use a meaningful encryption context. In this sample, we omit the
    # encryption context (no key pairs).
    assert all(
        (str(k, encoding="ascii"), str(v, encoding="ascii")) in decrypted_header.encryption_context.items() for (k, v) in encryptor_header.encryption_context.items()
    )

# hack in a test
import botocore
cycle_string("arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f", "abcdefg", botocore_session=botocore.session.Session())