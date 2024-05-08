# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Demonstrate an encrypt/decrypt cycle using a Required Encryption Context CMM.
A required encryption context CMM asks for required keys in the encryption context field
on encrypt such that they will not be stored on the message, but WILL be included in the header signature.
On decrypt, the client MUST supply the key/value pair(s) that were not stored to successfully decrypt the message.
"""
import sys

import boto3
# Ignore missing MPL for pylint, but the MPL is required for this example
# noqa pylint: disable=import-error
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateAwsKmsKeyringInput,
    CreateDefaultCryptographicMaterialsManagerInput,
    CreateRequiredEncryptionContextCMMInput,
)
from aws_cryptographic_materialproviders.mpl.references import ICryptographicMaterialsManager, IKeyring
from typing import Dict, List  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks
module_root_dir = '/'.join(__file__.split("/")[:-1])

sys.path.append(module_root_dir)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    kms_key_id: str
):
    """Creates a hierarchical keyring using the provided resources, then encrypts and decrypts a string with it."""
    # 1. Instantiate the encryption SDK client.
    #    This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
    #    which enforces that this client only encrypts using committing algorithm suites and enforces
    #    that this client will only decrypt encrypted messages that were created with a committing
    #    algorithm suite.
    #    This is the default commitment policy if you were to build the client as
    #    `client = aws_encryption_sdk.EncryptionSDKClient()`.

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    # 2. Create an encryption context.
    #    Most encrypted data should have an associated encryption context
    #    to protect integrity. This sample uses placeholder values.
    #    For more information see:
    #    blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management  # noqa: E501
    encryption_context: Dict[str, str] = {
        "key1": "value1",
        "key2": "value2",
        "requiredKey1": "requiredValue1",
        "requiredKey2": "requiredValue2",
    }

    # 3. Create list of required encryption context keys.
    #    This is a list of keys that must be present in the encryption context.
    required_encryption_context_keys: List[str] = ["requiredKey1", "requiredKey2"]

    # 4. Create the AWS KMS keyring.
    mpl: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )
    keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=kms_key_id,
        kms_client=boto3.client('kms', region_name="us-west-2")
    )
    kms_keyring: IKeyring = mpl.create_aws_kms_keyring(keyring_input)

    # 5. Create the required encryption context CMM.
    underlying_cmm: ICryptographicMaterialsManager = \
        mpl.create_default_cryptographic_materials_manager(
            CreateDefaultCryptographicMaterialsManagerInput(
                keyring=kms_keyring
            )
        )

    required_ec_cmm: ICryptographicMaterialsManager = \
        mpl.create_required_encryption_context_cmm(
            CreateRequiredEncryptionContextCMMInput(
                required_encryption_context_keys=required_encryption_context_keys,
                underlying_cmm=underlying_cmm,
            )
        )

    # 6. Encrypt the data
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        materials_manager=required_ec_cmm,
        encryption_context=encryption_context
    )

    # 7. Reproduce the encryption context.
    #    The reproduced encryption context MUST contain a value for
    #    every key in the configured required encryption context keys during encryption with
    #    Required Encryption Context CMM.
    reproduced_encryption_context: Dict[str, str] = {
        "requiredKey1": "requiredValue1",
        "requiredKey2": "requiredValue2",
    }

    # 8. Decrypt the data
    plaintext_bytes_a, _ = client.decrypt(
        source=ciphertext,
        materials_manager=required_ec_cmm,
        encryption_context=reproduced_encryption_context
    )
    assert plaintext_bytes_a == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # We can also decrypt using the underlying CMM,
    # but must also provide the reproduced encryption context
    plaintext_bytes_a, _ = client.decrypt(
        source=ciphertext,
        materials_manager=underlying_cmm,
        encryption_context=reproduced_encryption_context
    )
    assert plaintext_bytes_a == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # 9. Extra: Demonstrate that if we don't provide the reproduced encryption context,
    #    decryption will fail.
    try:
        plaintext_bytes_a, _ = client.decrypt(
            source=ciphertext,
            materials_manager=required_ec_cmm,
            # No reproduced encryption context for required EC CMM-produced message makes decryption fail.
        )
        raise Exception("If this exception is raised, decryption somehow succeeded!")
    except AWSEncryptionSDKClientError:
        # Swallow specific expected exception.
        # We expect decryption to fail with an AWSEncryptionSDKClientError
        # since we did not provide reproduced encryption context when decrypting
        # a message encrypted with the requried encryption context CMM.
        pass

    # Same for the default CMM;
    # If we don't provide the reproduced encryption context, decryption will fail.
    try:
        plaintext_bytes_a, _ = client.decrypt(
            source=ciphertext,
            materials_manager=required_ec_cmm,
            # No reproduced encryption context for required EC CMM-produced message makes decryption fail.
        )
        raise Exception("If this exception is raised, decryption somehow succeeded!")
    except AWSEncryptionSDKClientError:
        # Swallow specific expected exception.
        # We expect decryption to fail with an AWSEncryptionSDKClientError
        # since we did not provide reproduced encryption context when decrypting
        # a message encrypted with the requried encryption context CMM,
        # even though we are using a default CMM on decrypt.
        pass
