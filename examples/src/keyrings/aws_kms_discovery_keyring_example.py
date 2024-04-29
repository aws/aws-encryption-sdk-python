# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example sets up the AWS KMS Discovery Keyring

AWS KMS discovery keyring is an AWS KMS keyring that doesn't specify any wrapping keys.

The AWS Encryption SDK provides a standard AWS KMS discovery keyring and a discovery keyring
for AWS KMS multi-Region keys. For information about using multi-Region keys with the
AWS Encryption SDK, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks

Because it doesn't specify any wrapping keys, a discovery keyring can't encrypt data.
If you use a discovery keyring to encrypt data, alone or in a multi-keyring, the encrypt
operation fails. The exception is the AWS Encryption SDK for C, where the encrypt operation
ignores a standard discovery keyring, but fails if you specify a multi-Region discovery
keyring, alone or in a multi-keyring.

When decrypting, a discovery keyring allows the AWS Encryption SDK to ask AWS KMS to decrypt
any encrypted data key by using the AWS KMS key that encrypted it, regardless of who owns or
has access to that AWS KMS key. The call succeeds only when the caller has kms:Decrypt
permission on the AWS KMS key.

This example creates a KMS Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context. This encrypted ciphertext is then decrypted using the Discovery keyring.
This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
4. Decryption is only possible if the Discovery Keyring contains the correct AWS Account ID's to
which the KMS key used for encryption belongs
These sanity checks are for demonstration in the example only. You do not need these in your code.

For more information on how to use KMS keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
"""
import sys

import boto3
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput, CreateAwsKmsDiscoveryKeyringInput, DiscoveryFilter
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
MODULE_ROOT_DIR = '/'.join(__file__.split("/")[:-1])

sys.path.append(MODULE_ROOT_DIR)

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring(
    kms_key_id: str
):
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS Discovery Keyring.

    Usage: encrypt_and_decrypt_with_keyring(kms_key_id)
    :param kms_key_id: KMS Key identifier for the KMS key you want to use for creating
    the kms_keyring used for encryption
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

    # 5. Encrypt the data for the encryptionContext
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=encrypt_kms_keyring,
        encryption_context=encryption_context
    )

    # 6. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 7. Now create a Discovery keyring to use for decryption. We'll add a discovery filter
    # so that we limit the set of ciphertexts we are willing to decrypt to only ones
    # created by KMS keys in our account and partition.

    discovery_keyring_input: CreateAwsKmsDiscoveryKeyringInput = CreateAwsKmsDiscoveryKeyringInput(
        kms_client=kms_client,
        discovery_filter=DiscoveryFilter(
            account_ids=["658956600833"],
            partition="aws"
        )
    )

    discovery_keyring: IKeyring = mat_prov.create_aws_kms_discovery_keyring(
        input=discovery_keyring_input
    )

    # 8. Decrypt your encrypted data using the discovery keyring.
    # On Decrypt, the header of the encrypted message (ciphertext) will be parsed.
    # The header contains the Encrypted Data Keys (EDKs), which, if the EDK
    # was encrypted by a KMS Keyring, includes the KMS Key ARN.
    # The Discovery Keyring filters these EDKs for
    # EDKs encrypted by Single Region OR Multi Region KMS Keys.
    # If a Discovery Filter is present, these KMS Keys must belong
    # to an AWS Account ID in the discovery filter's AccountIds and
    # must be from the discovery filter's partition.
    # Finally, KMS is called to decrypt each filtered EDK until an EDK is
    # successfully decrypted. The resulting data key is used to decrypt the
    # ciphertext's message.
    # If all calls to KMS fail, the decryption fails.

    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=discovery_keyring
    )

    # 9. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 10. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA

    # 11. Demonstrate that if the Discovery keyring (Bob's) doesn't have the correct account id's,
    # the decrypt will fail with an error message
    discovery_keyring_input_bob: CreateAwsKmsDiscoveryKeyringInput = \
        CreateAwsKmsDiscoveryKeyringInput(
            kms_client=kms_client,
            discovery_filter=DiscoveryFilter(
                account_ids=["658956600834"],
                partition="aws"
            )
        )

    discovery_keyring_bob: IKeyring = mat_prov.create_aws_kms_discovery_keyring(
        input=discovery_keyring_input_bob
    )

    # Decrypt the ciphertext using Bob's discovery keyring which doesn't contain the required
    # Account ID's for the KMS keyring used for encryption
    try:
        plaintext_bytes, _ = client.decrypt(
            source=ciphertext,
            keyring=discovery_keyring_bob
        )

        raise AssertionError("Decrypt using discovery keyring with wrong AWS Account ID should"
                             + "raise AWSEncryptionSDKClientError")
    except AWSEncryptionSDKClientError:
        pass
