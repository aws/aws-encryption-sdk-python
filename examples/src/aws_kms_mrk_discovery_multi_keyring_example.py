# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the AWS KMS MRK (multi-region key) Discovery Multi Keyring

AWS KMS MRK Discovery Multi Keyring is composed of multiple MRK discovery keyrings.

The AWS KMS discovery keyring is an AWS KMS keyring that doesn't specify any wrapping keys.

When decrypting, an MRK discovery keyring allows the AWS Encryption SDK to ask AWS KMS to decrypt
any encrypted data key by using the AWS KMS MRK that encrypted it, regardless of who owns or
has access to that AWS KMS key. The call succeeds only when the caller has kms:Decrypt
permission on the AWS KMS MRK.

The AWS Encryption SDK provides a standard AWS KMS discovery keyring and a discovery keyring
for AWS KMS multi-Region keys. Because it doesn't specify any wrapping keys, a discovery keyring
can't encrypt data. If you use a discovery keyring to encrypt data, alone or in a multi-keyring,
the encrypt operation fails.

The AWS Key Management Service (AWS KMS) MRK keyring interacts with AWS KMS to
create, encrypt, and decrypt data keys with multi-region AWS KMS keys (MRKs).
This example creates a KMS MRK Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This encrypted ciphertext is then decrypted using an
MRK Discovery Multi keyring. This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

For information about using multi-Region keys with the AWS Encryption SDK, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks

For more info on KMS MRKs (multi-region keys), see the KMS documentation:
https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html

For more information on how to use KMS Discovery keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
"""
import sys

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateAwsKmsMrkDiscoveryMultiKeyringInput,
    CreateAwsKmsMrkKeyringInput,
    DiscoveryFilter,
)
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
MODULE_ROOT_DIR = '/'.join(__file__.split("/")[:-1])

sys.path.append(MODULE_ROOT_DIR)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    mrk_key_id_encrypt: str,
    mrk_encrypt_region: str,
    aws_account_id: str,
    aws_regions: list[str]
):
    """Demonstrate decryption using an AWS KMS MRK Discovery Multi keyring.

    Since discovery keyrings cannot be used to encrypt, we use KMS MRK keyring for encryption
    Usage: encrypt_and_decrypt_with_keyring(mrk_key_id_encrypt,
                                            mrk_encrypt_region,
                                            aws_account_id,
                                            aws_regions)
    :param mrk_key_id_encrypt: KMS Key identifier for the KMS key located in your
    default region, which you want to use for encryption of your data keys
    :type mrk_key_id_encrypt: string
    :param mrk_encrypt_region: AWS Region for encryption of your data keys. This should
    be the region of the mrk_key_id_encrypt
    :type mrk_encrypt_region: string
    :param aws_account_id: AWS Account ID to use in the discovery filter
    :type aws_account_id: string
    :param aws_regions: AWS Regions to use in the the discovery filter
    :type aws_regions: list[string]

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

    # 3. Create the keyring that determines how your data keys are protected.
    # Although this example highlights Discovery keyrings, Discovery keyrings cannot
    # be used to encrypt, so for encryption we create an MRK keyring without discovery mode.

    # Create a keyring that will encrypt your data, using a KMS MRK in the first region.
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # Create a boto3 client for KMS in the first region.
    encrypt_kms_client = boto3.client('kms', region_name=mrk_encrypt_region)

    encrypt_keyring_input: CreateAwsKmsMrkKeyringInput = CreateAwsKmsMrkKeyringInput(
        kms_key_id=mrk_key_id_encrypt,
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

    # 6. Now create a MRK Discovery Multi Keyring to use for decryption.
    # We'll add a discovery filter to limit the set of encrypted data keys
    # we are willing to decrypt to only ones created by KMS keys in select
    # accounts and the partition `aws`.
    # MRK Discovery keyrings also filter encrypted data keys by the region
    # the keyring is created with.
    decrypt_discovery_multi_keyring_input: CreateAwsKmsMrkDiscoveryMultiKeyringInput = \
        CreateAwsKmsMrkDiscoveryMultiKeyringInput(
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
    decrypt_discovery_keyring: IKeyring = mat_prov.create_aws_kms_mrk_discovery_multi_keyring(
        input=decrypt_discovery_multi_keyring_input
    )

    # 7. Decrypt your encrypted data using the discovery multi keyring.
    # On Decrypt, the header of the encrypted message (ciphertext) will be parsed.
    # The header contains the Encrypted Data Keys (EDKs), which, if the EDK
    # was encrypted by a KMS Keyring, includes the KMS Key ARN.
    # For each member of the Multi Keyring, every EDK will try to be decrypted until a decryption
    # is successful.
    # Since every member of the Multi Keyring is a Discovery Keyring:
    #   Each Keyring will filter the EDKs by the Discovery Filter and the Keyring's region.
    #      For each filtered EDK, the keyring will attempt decryption with the keyring's client.
    # All of this is done serially, until a success occurs or all keyrings have failed
    # all (filtered) EDKs. KMS MRK Discovery Keyrings will attempt to decrypt
    # Multi Region Keys (MRKs) and regular KMS Keys.
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=decrypt_discovery_keyring
    )

    # 8. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 9. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA
