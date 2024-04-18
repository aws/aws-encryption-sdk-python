# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the KMS Keyring
"""
import sys

import boto3

from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy


# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
module_root_dir = '/'.join(__file__.split("/")[:-1])

sys.path.append(module_root_dir)

EXAMPLE_DATA: bytes = b"Hello World"

def encrypt_and_decrypt_with_keyring(
    kms_key_id: str
):
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS keyring."""

    """
    1. Instantiate the encryption SDK client.
       This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
       which enforces that this client only encrypts using committing algorithm suites and enforces
       that this client will only decrypt encrypted messages that were created with a committing
       algorithm suite.
       This is the default commitment policy if you were to build the client as
       `client = aws_encryption_sdk.EncryptionSDKClient()`.
    """
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    """
    2. Create boto3 clients for KMS.
    """
    kms_client = boto3.client('kms', region_name="us-west-2")

    """
    3. Instantiate the Material Providers
    """
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    """
    4. Create encryption context
    Remember that your encryption context is NOT SECRET.
    https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    """
    encryption_context: Dict[str, str] = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    """
    5. Create the KMS keyring
    """
    keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=kms_key_id,
        kms_client=kms_client
    )

    kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=keyring_input
    )

    """
    6. Encrypt the data for the encryptionContext
    """
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=kms_keyring,
        encryption_context=encryption_context
    )

    """
    7. Demonstrate that the ciphertext and plaintext are different.
    """
    assert ciphertext != EXAMPLE_DATA, "Ciphertext and plaintext data are the same. Invalid encryption"
    
    """
    8. Decrypt your encrypted data using the same keyring you used on encrypt.
    You do not need to specify the encryption context on decrypt
    because the header of the encrypted message includes the encryption context.
    """
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=kms_keyring
    )

    """
    9. Demonstrate that the encryption context is correct in the decrypted message header
    """
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], "Encryption context does not match expected values"

    """
    10. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    """
    assert plaintext_bytes == EXAMPLE_DATA