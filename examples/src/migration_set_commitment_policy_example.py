# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example configures a client with a specific commitment policy for the
AWS Encryption SDK client, then encrypts and decrypts data using an AWS KMS Keyring.

The commitment policy in this example (FORBID_ENCRYPT_ALLOW_DECRYPT) should only be
used as part of a migration from version 1.x to 2.x, or for advanced users with
specialized requirements. Most AWS Encryption SDK users should use the default
commitment policy (REQUIRE_ENCRYPT_REQUIRE_DECRYPT).

This example creates a KMS Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context for the commitment policy FORBID_ENCRYPT_ALLOW_DECRYPT.
This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

For more information on setting your commitment policy, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#commitment-policy
"""

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    kms_key_id: str
):
    """Demonstrate how to set your commitment policy for migration.

    Usage: encrypt_and_decrypt_with_keyring(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use for encryption and
    decryption of your data keys.
    :type kms_key_id: string

    For more information on KMS Key identifiers, see
    https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
    """
    # 1. Instantiate the encryption SDK client.
    # This example builds the client with the FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy,
    # which enforces that this client cannot encrypt with key commitment
    # and it can decrypt ciphertexts encrypted with or without key commitment.
    # The default commitment policy if you were to build the client as
    # `client = aws_encryption_sdk.EncryptionSDKClient()` is REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
    # We recommend that AWS Encryption SDK users use the default commitment policy
    # (REQUIRE_ENCRYPT_REQUIRE_DECRYPT) whenever possible.
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    # 2. Create a boto3 client for KMS.
    kms_client = boto3.client('kms', region_name="us-west-2")

    # 3. Create encryption context.
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

    # 4. Create a KMS keyring
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

    # 5. Encrypt the data with the encryptionContext. Make sure you use a non-committing algorithm
    # with the commitment policy FORBID_ENCRYPT_ALLOW_DECRYPT. Otherwise client.encrypt() will throw
    # aws_encryption_sdk.exceptions.ActionNotAllowedError. By default for
    # FORBID_ENCRYPT_ALLOW_DECRYPT, the algorithm used is
    # AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 which is a non-committing algorithm.
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=kms_keyring,
        encryption_context=encryption_context
    )

    # 6. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 7. Decrypt your encrypted data using the same keyring you used on encrypt.
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=kms_keyring
    )

    # 8. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 9. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
