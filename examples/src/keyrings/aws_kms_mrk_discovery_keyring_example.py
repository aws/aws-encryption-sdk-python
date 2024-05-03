# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the AWS KMS MRK (multi-region key) Discovery Keyring

AWS KMS discovery keyring is an AWS KMS keyring that doesn't specify any wrapping keys.
The AWS Encryption SDK provides a standard AWS KMS discovery keyring and a discovery keyring
for AWS KMS multi-Region keys. Because it doesn't specify any wrapping keys, a discovery keyring
can't encrypt data. If you use a discovery keyring to encrypt data, alone or in a multi-keyring,
the encrypt operation fails.

When decrypting, an MRK discovery keyring allows the AWS Encryption SDK to ask AWS KMS to decrypt
any encrypted data key by using the AWS KMS MRK that encrypted it, regardless of who owns or
has access to that AWS KMS key. The call succeeds only when the caller has kms:Decrypt
permission on the AWS KMS MRK.

The AWS Key Management Service (AWS KMS) MRK keyring interacts with AWS KMS to
create, encrypt, and decrypt data keys with multi-region AWS KMS keys (MRKs).
This example creates a KMS MRK Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This encrypted ciphertext is then decrypted using an
MRK Discovery keyring. This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

For information about using multi-Region keys with the AWS Encryption SDK, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks

For more info on KMS MRK (multi-region keys), see the KMS documentation:
https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html

For more information on how to use KMS Discovery keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
"""
import sys

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateAwsKmsMrkDiscoveryKeyringInput,
    CreateAwsKmsMrkKeyringInput,
    DiscoveryFilter,
)
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
MODULE_ROOT_DIR = '/'.join(__file__.split("/")[:-1])

sys.path.append(MODULE_ROOT_DIR)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    mrk_key_id_encrypt: str,
    aws_account_id: str,
    mrk_encrypt_region: str,
    mrk_replica_decrypt_region: str
):
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS MRK Discovery keyring.

    Usage: encrypt_and_decrypt_with_keyring(mrk_key_id_encrypt,
                                            aws_account_id,
                                            mrk_encrypt_region,
                                            mrk_replica_decrypt_region)
    :param mrk_key_id_encrypt: KMS Key identifier for the KMS key located in your
    default region, which you want to use for encryption of your data keys
    :type mrk_key_id_encrypt: string
    :param aws_account_id: AWS Account ID to use in the discovery filter
    :type aws_account_id: string
    :param mrk_encrypt_region: AWS Region for encryption of your data keys. This should
    be the region of the mrk_key_id_encrypt.
    :type mrk_encrypt_region: string
    :param mrk_replica_decrypt_region: AWS Region for decryption of your data keys.
    This example assumes you have already replicated your mrk_key_id_encrypt to the
    region mrk_replica_decrypt_region. Therfore, this mrk_replica_decrypt_region should
    be the region of the mrk replica key id. However, since we are using a discovery keyring,
    we don't need to provide the mrk replica key id
    :type mrk_replica_decrypt_region: string

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

    # 6. Now create a Discovery keyring to use for decryption.
    # In order to illustrate the MRK behavior of this keyring, we configure
    # the keyring to use the second KMS region where the MRK (mrk_key_id_encrypt) is replicated to.
    # This example assumes you have already replicated your key, but since we
    # are using a discovery keyring, we don't need to provide the mrk replica key id

    # Create a boto3 client for KMS in the second region.
    decrypt_kms_client = boto3.client('kms', region_name=mrk_replica_decrypt_region)

    decrypt_discovery_keyring_input: CreateAwsKmsMrkDiscoveryKeyringInput = \
        CreateAwsKmsMrkDiscoveryKeyringInput(
            kms_client=decrypt_kms_client,
            region=mrk_replica_decrypt_region,
            discovery_filter=DiscoveryFilter(
                account_ids=[aws_account_id],
                partition="aws"
            )
        )

    decrypt_discovery_keyring: IKeyring = mat_prov.create_aws_kms_mrk_discovery_keyring(
        input=decrypt_discovery_keyring_input
    )

    # 7. Decrypt your encrypted data using the discovery keyring.
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
