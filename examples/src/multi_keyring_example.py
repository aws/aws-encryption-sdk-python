# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the Multi Keyring

A multi-keyring is a keyring that consists of one or more individual keyrings of the
same or a different type. The effect is like using several keyrings in a series.
When you use a multi-keyring to encrypt data, any of the wrapping keys in any of its
keyrings can decrypt that data.

When you create a multi-keyring to encrypt data, you designate one of the keyrings as
the generator keyring. All other keyrings are known as child keyrings. The generator keyring
generates and encrypts the plaintext data key. Then, all of the wrapping keys in all of the
child keyrings encrypt the same plaintext data key. The multi-keyring returns the plaintext
key and one encrypted data key for each wrapping key in the multi-keyring. If you create a
multi-keyring with no generator keyring, you can use it to decrypt data, but not to encrypt.
If the generator keyring is a KMS keyring, the generator key in the AWS KMS keyring generates
and encrypts the plaintext key. Then, all additional AWS KMS keys in the AWS KMS keyring,
and all wrapping keys in all child keyrings in the multi-keyring, encrypt the same plaintext key.

When decrypting, the AWS Encryption SDK uses the keyrings to try to decrypt one of the encrypted
data keys. The keyrings are called in the order that they are specified in the multi-keyring.
Processing stops as soon as any key in any keyring can decrypt an encrypted data key.

This example creates a Multi Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Decryption of ciphertext is possible using the multi_keyring,
and every one of the keyrings from the multi_keyring separately
3. All decrypted plaintext value match EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

This example creates a multi_keyring using a KMS keyring as generator keyring and a raw AES keyring
as a child keyring. You can use different combinations of keyrings in the multi_keyring.

For more information on how to use Multi keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-multi-keyring.html
"""
import secrets

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    AesWrappingAlg,
    CreateAwsKmsKeyringInput,
    CreateMultiKeyringInput,
    CreateRawAesKeyringInput,
)
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    kms_key_id: str
):
    """Demonstrate an encrypt/decrypt cycle using a Multi keyring.
    The multi_keyring is created using a KMS keyring as generator keyring and a raw AES keyring
    as a child keyring. Therefore, we take a kms_key_id as input

    Usage: encrypt_and_decrypt_with_keyring(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use for encryption and
    decryption of your data keys in the kms_keyring, that is in-turn used in the multi_keyring
    :type kms_key_id: string

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

    # 4. Initialize the material providers library
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # 5. Create a KMS keyring
    kms_keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=kms_key_id,
        kms_client=kms_client
    )

    kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=kms_keyring_input
    )

    # 6. Create a raw AES keyring to additionally encrypt under as child_keyring

    # The key namespace and key name are defined by you.
    # and are used by the Raw AES keyring to determine
    # whether it should attempt to decrypt an encrypted data key.
    # For more information, see
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-aes-keyring.html
    key_name_space = "Some managed raw keys"
    key_name = "My 256-bit AES wrapping key"

    # Generate a 256-bit AES key to use with your raw AES keyring.
    # Here, the input to secrets.token_bytes() = 32 bytes = 256 bits
    static_key = secrets.token_bytes(32)

    raw_aes_keyring_input: CreateRawAesKeyringInput = CreateRawAesKeyringInput(
        key_namespace=key_name_space,
        key_name=key_name,
        wrapping_key=static_key,
        wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
    )

    raw_aes_keyring: IKeyring = mat_prov.create_raw_aes_keyring(
        input=raw_aes_keyring_input
    )

    # 7. Create a multi_keyring that consists of the previously created keyrings.
    # When using this multi_keyring to encrypt data, either `kms_keyring` or
    # `raw_aes_keyring` (or a multi_keyring containing either) may be used to decrypt the data.
    multi_keyring_input: CreateMultiKeyringInput = CreateMultiKeyringInput(
        generator=kms_keyring,
        child_keyrings=[raw_aes_keyring]
    )

    multi_keyring: IKeyring = mat_prov.create_multi_keyring(
        input=multi_keyring_input
    )

    # 8. Encrypt the data with the encryptionContext
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=multi_keyring,
        encryption_context=encryption_context
    )

    # 9. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 10a. Decrypt your encrypted data using the same multi_keyring you used on encrypt.
    plaintext_bytes_multi_keyring, _ = client.decrypt(
        source=ciphertext,
        keyring=multi_keyring,
        # Provide the encryption context that was supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 10b. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_multi_keyring == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # Because you used a multi_keyring on Encrypt, you can use either the
    # `kms_keyring` or `raw_aes_keyring` individually to decrypt the data.

    # 11. Demonstrate that you can successfully decrypt data using just the `kms_keyring`
    # directly.
    # (This is an example for demonstration; you do not need to do this in your own code.)

    # 11a. Decrypt your encrypted data using the kms_keyring.
    plaintext_bytes_kms_keyring, _ = client.decrypt(
        source=ciphertext,
        keyring=kms_keyring,
        # Provide the encryption context that was supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 11b. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_kms_keyring == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # 12. Demonstrate that you can also successfully decrypt data using the `raw_aes_keyring`
    # directly.
    # (This is an example for demonstration; you do not need to do this in your own code.)

    # 12a. Decrypt your encrypted data using the raw_aes_keyring.
    plaintext_bytes_raw_aes_keyring, _ = client.decrypt(
        source=ciphertext,
        keyring=raw_aes_keyring,
        # Provide the encryption context that was supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 12b. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_raw_aes_keyring == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
