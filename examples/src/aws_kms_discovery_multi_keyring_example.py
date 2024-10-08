# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the AWS KMS Discovery Multi Keyring and demonstrates decryption
using a Multi-Keyring containing multiple AWS KMS Discovery Keyrings.

The AWS Encryption SDK provides a standard AWS KMS discovery keyring and a discovery keyring
for AWS KMS multi-Region keys. For information about using multi-Region keys with the
AWS Encryption SDK, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks

Because it doesn't specify any wrapping keys, a discovery keyring can't encrypt data.
If you use a discovery keyring to encrypt data, alone or in a multi-keyring, the encrypt
operation fails.

When decrypting, a discovery keyring allows the AWS Encryption SDK to ask AWS KMS to decrypt
any encrypted data key by using the AWS KMS key that encrypted it, regardless of who owns or
has access to that AWS KMS key. The call succeeds only when the caller has kms:Decrypt
permission on the AWS KMS key.

This example creates a KMS Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This encrypted ciphertext is then decrypted using the Discovery Multi
keyring. This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

For more information on how to use KMS Discovery keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
"""

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateAwsKmsDiscoveryMultiKeyringInput,
    CreateAwsKmsKeyringInput,
    DiscoveryFilter,
)
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    kms_key_id: str,
    aws_account_id: str,
    aws_regions: list
):
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS Discovery Multi Keyring.

    Usage: encrypt_and_decrypt_with_keyring(kms_key_id, aws_account_id, aws_regions)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use for creating
    the kms_keyring used for encryption
    :type kms_key_id: string
    :param aws_account_id: AWS Account ID to use in the discovery filter
    :type aws_account_id: string
    :param aws_regions: List of AWS Regions to use for creating the discovery multi keyring
    :type aws_regions: list[string]

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

    # 4. Create the keyring that determines how your data keys are protected.
    # Although this example highlights Discovery keyrings, Discovery keyrings cannot
    # be used to encrypt, so for encryption we create a KMS keyring without discovery mode.
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    kms_keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
        kms_key_id=kms_key_id,
        kms_client=kms_client
    )

    encrypt_kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
        input=kms_keyring_input
    )

    # 5. Encrypt the data with the encryptionContext
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=encrypt_kms_keyring,
        encryption_context=encryption_context
    )

    # 6. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 7. Now create a Discovery Multi keyring to use for decryption. We'll add a discovery filter
    # so that we limit the set of ciphertexts we are willing to decrypt to only ones
    # created by KMS keys in our account and partition.
    discovery_multi_keyring_input: CreateAwsKmsDiscoveryMultiKeyringInput = \
        CreateAwsKmsDiscoveryMultiKeyringInput(
            regions=aws_regions,
            discovery_filter=DiscoveryFilter(
                account_ids=[aws_account_id],
                partition="aws"
            )
        )

    # This is a Multi Keyring composed of Discovery Keyrings.
    # There is a keyring for every region in `regions`.
    # All the keyrings have the same Discovery Filter.
    # Each keyring has its own KMS Client, which is created for the keyring's region.
    discovery_multi_keyring: IKeyring = mat_prov.create_aws_kms_discovery_multi_keyring(
        input=discovery_multi_keyring_input
    )

    # 8. On Decrypt, the header of the encrypted message (ciphertext) will be parsed.
    # The header contains the Encrypted Data Keys (EDKs), which, if the EDK
    # was encrypted by a KMS Keyring, includes the KMS Key ARN.
    # For each member of the Multi Keyring, every EDK will try to be decrypted until a decryption
    # is successful.
    # Since every member of the Multi Keyring is a Discovery Keyring:
    #   Each Keyring will filter the EDKs by the Discovery Filter
    #       For the filtered EDKs, the keyring will try to decrypt it with the keyring's client.
    # All of this is done serially, until a success occurs or all keyrings have
    # failed all (filtered) EDKs.
    # KMS Discovery Keyrings will attempt to decrypt Multi Region Keys (MRKs) and regular KMS Keys.
    plaintext_bytes, _ = client.decrypt(
        source=ciphertext,
        keyring=discovery_multi_keyring,
        # Provide the encryption context that was supplied to the encrypt method
        encryption_context=encryption_context,
    )

    # 9. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
