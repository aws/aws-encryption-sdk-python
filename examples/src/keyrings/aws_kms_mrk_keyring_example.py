# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the KMS MRK (multi-region key) Keyring

KMS MRK keyring interacts with AWS Key Management Service (AWS KMS) to create, encrypt,
and decrypt data keys using AWS KMS defined Customer Master Keys (CMKs).
This example creates a KMS MRK Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

AWS KMS MRK keyrings can be used independently or in a multi-keyring with other keyrings
of the same or a different type.

For more information on how to use KMS keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html

For more info on KMS MRK (multi-region keys), see the KMS documentation:
https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
"""
import sys

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsMrkKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
MODULE_ROOT_DIR = '/'.join(__file__.split("/")[:-1])

sys.path.append(MODULE_ROOT_DIR)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    encrypt_kms_key_id: str,
    decrypt_kms_key_id: str,
    encrypt_region: str,
    decrypt_region: str
):
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS keyring.

    Usage: encrypt_and_decrypt_with_keyring(encrypt_kms_key_id,
                                            decrypt_kms_key_id,
                                            encrypt_region,
                                            decrypt_region)
    :param encrypt_kms_key_id: KMS Key identifier for the KMS key you want to use
    for encryption of your data keys.
    :type encrypt_kms_key_id: string
    :param decrypt_kms_key_id: KMS Key identifier for the KMS key you want to use
    for decryption of your data keys.
    :type decrypt_kms_key_id: string
    :param encrypt_region: AWS Region for encryption of your data keys
    :type encrypt_region: string
    :param decrypt_region: AWS Region for decryption of your data keys
    :type decrypt_region: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    # 1. Instantiate the encryption SDK client.
    # This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
    # which enforces that this client only encrypts using committing algorithm suites and enforces
    # that this client will only decrypt encrypted messages that were created with a committing
    # algorithm suite.
    # This is the default commitment policy if you were to build the client as
    # `client = aws_encryption_sdk.EncryptionSDKClient()`.
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    # 2. Create encryption context.
    # Remember that your encryption context is NOT SECRET.
    # For more information, see
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context: Dict[str, str] = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # 3. Create a keyring that will encrypt your data, using a KMS MRK key in the first region.
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # Create a boto3 client for KMS in the first region.
    encrypt_kms_client = boto3.client('kms', region_name=encrypt_region)

    encrypt_keyring_input: CreateAwsKmsMrkKeyringInput = CreateAwsKmsMrkKeyringInput(
        kms_key_id=encrypt_kms_key_id,
        kms_client=encrypt_kms_client
    )

    encrypt_keyring: IKeyring = mat_prov.create_aws_kms_mrk_keyring(
        input=encrypt_keyring_input
    )

    # 4. Encrypt the data with the encryptionContext using the encrypt_keyring.
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=encrypt_keyring,
        encryption_context=encryption_context
    )

    # 5. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 6. Create a keyring that will decrypt your data, using the same KMS MRK key replicated
    # to the second region. This example assumes you have already replicated your key

    # Create a boto3 client for KMS in the second region.
    decrypt_kms_client = boto3.client('kms', region_name=decrypt_region)

    decrypt_keyring_input: CreateAwsKmsMrkKeyringInput = CreateAwsKmsMrkKeyringInput(
        kms_key_id=decrypt_kms_key_id,
        kms_client=decrypt_kms_client
    )

    decrypt_keyring: IKeyring = mat_prov.create_aws_kms_mrk_keyring(
        input=decrypt_keyring_input
    )

    # 7. Decrypt your encrypted data using the same keyring you used on encrypt.
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=decrypt_keyring
    )

    # 8. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 9. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA
