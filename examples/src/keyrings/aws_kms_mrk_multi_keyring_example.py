# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the KMS MRK Multi Keyring

The AWS Key Management Service (AWS KMS) MRK keyring interacts with AWS KMS to
create, encrypt, and decrypt data keys with AWS KMS MRK keys.
The KMS MRK multi-keyring consists of one or more individual keyrings of the
same or different type. The keys can either be regular KMS keys or MRKs.
The effect is like using several keyrings in a series.

This example creates a AwsKmsMrkMultiKeyring using an mrk_key_id (generator) and a kms_key_id
as a child key, and then encrypts a custom input EXAMPLE_DATA with an encryption context.
Either KMS Key individually is capable of decrypting data encrypted under this keyring.
This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
4. Ciphertext can be decrypted using an AwsKmsMrkKeyring containing a replica of the
   MRK (from the multi-keyring used for encryption) copied from the first region into
   the second region
These sanity checks are for demonstration in the example only. You do not need these in your code.

For more information on how to use KMS keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html

For more info on KMS MRK (multi-region keys), see the KMS documentation:
https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
"""
import sys

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsMrkKeyringInput, CreateAwsKmsMrkMultiKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
MODULE_ROOT_DIR = '/'.join(__file__.split("/")[:-1])

sys.path.append(MODULE_ROOT_DIR)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    mrk_key_id: str,
    kms_key_id: str,
    mrk_replica_key_id: str,
    second_region: str
):
    """Demonstrate an encrypt/decrypt cycle using a Multi-Keyring made
       up of multiple AWS KMS MRK Keyrings

    Usage: encrypt_and_decrypt_with_keyring(mrk_key_id,
                                            kms_key_id,
                                            mrk_replica_key_id,
                                            second_region)
    :param mrk_key_id: KMS Key identifier for an AWS KMS multi-region key (MRK) located in your
    default region
    :type mrk_key_id: string
    :param kms_key_id: KMS Key identifier for a KMS key, possibly located in a different region
    than the MRK
    :type kms_key_id: string
    :param mrk_replica_key_id: KMS Key identifier for an MRK that is a replica of the
    `mrk_key_id` in a second region.
    :type mrk_replica_key_id: string
    :param second_region: The second region where the MRK replica is located
    :type second_region: string

    For more information on KMS Key identifiers for multi-region keys, see
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

    # 3. Create an AwsKmsMrkMultiKeyring that protects your data under two different KMS Keys.
    # The Keys can either be regular KMS keys or MRKs.
    # Either KMS Key individually is capable of decrypting data encrypted under this keyring.
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    kms_mrk_multi_keyring_input: CreateAwsKmsMrkMultiKeyringInput =\
        CreateAwsKmsMrkMultiKeyringInput(
            generator=mrk_key_id,
            kms_key_ids=[kms_key_id]
        )

    kms_mrk_multi_keyring: IKeyring = mat_prov.create_aws_kms_mrk_multi_keyring(
        input=kms_mrk_multi_keyring_input
    )

    # 4. Encrypt the data with the encryptionContext using the kms_mrk_multi_keyring.
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=kms_mrk_multi_keyring,
        encryption_context=encryption_context
    )

    # 5. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 6. Decrypt your encrypted data using the same AwsKmsMrkMultiKeyring you used on encrypt.
    # It will decrypt the data using the generator key (in this case, the MRK), since that is
    # the first available KMS key on the keyring that is capable of decrypting the data.
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=kms_mrk_multi_keyring
    )

    # 7. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 8. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA

    # Demonstrate that a single AwsKmsMrkKeyring configured with a replica of the MRK from the
    # multi-keyring used to encrypt the data is also capable of decrypting the data.
    # (This is an example for demonstration; you do not need to do this in your own code.)

    # 9. Create a single AwsKmsMrkKeyring with the replica KMS MRK from the second region.

    # Create a boto3 client for KMS in the second region.
    second_region_kms_client = boto3.client('kms', region_name=second_region)

    second_region_mrk_keyring_input: CreateAwsKmsMrkKeyringInput = CreateAwsKmsMrkKeyringInput(
        kms_key_id=mrk_replica_key_id,
        kms_client=second_region_kms_client
    )

    second_region_mrk_keyring: IKeyring = mat_prov.create_aws_kms_mrk_keyring(
        input=second_region_mrk_keyring_input
    )

    # 10. Decrypt your encrypted data using the second region AwsKmsMrkKeyring
    plaintext_bytes_second_region, dec_header_second_region = client.decrypt(
        source=ciphertext,
        keyring=second_region_mrk_keyring
    )

    # 11. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header_second_region.encryption_context[k], \
            "Encryption context does not match expected values"

    # 12. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes_second_region == EXAMPLE_DATA

    # Not shown in this example: A KMS Keyring created with `kms_key_id` could also
    # decrypt this message.
