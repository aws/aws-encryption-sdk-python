# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the AWS KMS Multi Keyring made up of multiple AWS KMS Keyrings.

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

This example creates a multi_keyring using a KMS keyring as generator keyring and
another KMS keyring as a child keyring.

For more information on how to use Multi keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-multi-keyring.html
"""

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput, CreateAwsKmsMultiKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    default_region_kms_key_id: str,
    second_region_kms_key_id: str,
    default_region: str,
    second_region: str
):
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS Multi keyring.
    The multi_keyring is created using a KMS keyring as generator keyring and another KMS keyring
    as a child keyring. For this example, `default_region_kms_key_id` is the generator key id
    for a KMS key located in your default region, and `second_region_kms_key_id` is the KMS key id
    for a KMS Key located in some second region.

    Usage: encrypt_and_decrypt_with_keyring(default_region_kms_key_id,
                                            second_region_kms_key_id,
                                            default_region,
                                            second_region)
    :param default_region_kms_key_id: KMS Key identifier for the default region KMS key you want to
    use as a generator keyring
    :type default_region_kms_key_id: string
    :param second_region_kms_key_id: KMS Key identifier for the second region KMS key you want to
    use as a child keyring
    :type second_region_kms_key_id: string
    :param default_region: AWS Region for the default region KMS key
    :type default_region: string
    :param second_region: AWS Region for the second region KMS key
    :type second_region: string

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

    # 3. Create an AwsKmsMultiKeyring that protects your data under two different KMS Keys.
    # Either KMS Key individually is capable of decrypting data encrypted under this Multi Keyring.
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    kms_multi_keyring_input: CreateAwsKmsMultiKeyringInput = CreateAwsKmsMultiKeyringInput(
        generator=default_region_kms_key_id,
        kms_key_ids=[second_region_kms_key_id]
    )

    kms_multi_keyring: IKeyring = mat_prov.create_aws_kms_multi_keyring(
        input=kms_multi_keyring_input
    )

    # 4. Encrypt the data with the encryptionContext
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=kms_multi_keyring,
        encryption_context=encryption_context
    )

    # 5. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 6a. Decrypt your encrypted data using the same multi_keyring you used on encrypt.
    plaintext_bytes_multi_keyring, _ = client.decrypt(
        source=ciphertext,
        keyring=kms_multi_keyring,
        # Verify that the encryption context in the result contains the
        # encryption context supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 6b. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_multi_keyring == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # Because you used a multi_keyring on Encrypt, you can use either of the two
    # kms keyrings individually to decrypt the data.

    # 7. Demonstrate that you can successfully decrypt data using a KMS keyring with just the
    # `default_region_kms_key_id` directly.
    # (This is an example for demonstration; you do not need to do this in your own code.)

    # 7a. Create a boto3 client for KMS for the default region.
    default_region_kms_client = boto3.client('kms', region_name=default_region)

    # 7b. Create KMS keyring
    default_region_kms_keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=default_region_kms_key_id,
        kms_client=default_region_kms_client
    )

    default_region_kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=default_region_kms_keyring_input
    )

    # 7c. Decrypt your encrypted data using the default_region_kms_keyring.
    plaintext_bytes_default_region_kms_keyring, _ = client.decrypt(
        source=ciphertext,
        keyring=default_region_kms_keyring,
        # Verify that the encryption context in the result contains the
        # encryption context supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 7d. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_default_region_kms_keyring == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"

    # 8. Demonstrate that you can also successfully decrypt data using a KMS keyring with just the
    # `second_region_kms_key_id` directly.
    # (This is an example for demonstration; you do not need to do this in your own code.)

    # 8a. Create a boto3 client for KMS for the second region.
    second_region_kms_client = boto3.client('kms', region_name=second_region)

    # 8b. Create KMS keyring
    second_region_kms_keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=second_region_kms_key_id,
        kms_client=second_region_kms_client
    )

    second_region_kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=second_region_kms_keyring_input
    )

    # 8c. Decrypt your encrypted data using the second_region_kms_keyring.
    plaintext_bytes_second_region_kms_keyring, _ = client.decrypt(
        source=ciphertext,
        keyring=second_region_kms_keyring,
        # Verify that the encryption context in the result contains the
        # encryption context supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 8d. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_second_region_kms_keyring == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
