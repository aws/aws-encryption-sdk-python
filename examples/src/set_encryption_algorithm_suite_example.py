# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example demonstrates how to set an algorithm suite while using the Raw AES Keyring
in the AWS Encryption SDK.

The algorithm suite used in the encrypt() method is the algorithm used to protect your
data using the data key. By setting this algorithm, you can configure the algorithm used
to encrypt and decrypt your data.

Algorithm suites can be set in a similar manner in other keyrings as well. However,
please make sure that you're using a logical algorithm suite that is compatible with your
keyring. For more information on algorithm suites supported by the AWS Encryption SDK, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html

The AES wrapping algorithm (AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16) protects your data key using
the user-provided wrapping key. In contrast, the algorithm suite used in the encrypt() method
is the algorithm used to protect your data using the data key. This example demonstrates setting the
latter, which is the algorithm suite for protecting your data. When the commitment policy is
REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the default algorithm used in the encrypt method is
AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, which is a committing and signing algorithm.
Signature verification ensures the integrity of a digital message as it goes across trust
boundaries. However, signature verification adds a significant performance cost to encryption
and decryption. If encryptors and decryptors are equally trusted, we can consider using an algorithm
suite that does not include signing. This example sets the algorithm suite as
AES_256_GCM_HKDF_SHA512_COMMIT_KEY, which is a committing but non-signing algorithm.
For more information on digital signatures, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#digital-sigs

This example creates a Raw AES Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context and the algorithm suite AES_256_GCM_HKDF_SHA512_COMMIT_KEY.
This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

For more information on how to use Raw AES keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-aes-keyring.html
"""
import secrets

from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import AesWrappingAlg, CreateRawAesKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict  # noqa pylint: disable=wrong-import-order

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.identifiers import AlgorithmSuite

EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_and_decrypt_with_keyring():
    """Demonstrate an encrypt/decrypt cycle using a Raw AES keyring.

    Usage: encrypt_and_decrypt_with_keyring()
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

    # 2. The key namespace and key name are defined by you.
    # and are used by the Raw AES keyring to determine
    # whether it should attempt to decrypt an encrypted data key.
    # For more information, see
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-aes-keyring.html
    key_name_space = "Some managed raw keys"
    key_name = "My 256-bit AES wrapping key"

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

    # 4. Generate a 256-bit AES wrapping key to use with your keyring.
    # In practice, you should get this key from a secure key management system such as an HSM.

    # Here, the input to secrets.token_bytes() = 32 bytes = 256 bits
    static_key = secrets.token_bytes(32)

    # 5. Create a Raw AES keyring
    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    # The wrapping algorithm here is NOT the algorithm suite we set in this example.
    keyring_input: CreateRawAesKeyringInput = CreateRawAesKeyringInput(
        key_namespace=key_name_space,
        key_name=key_name,
        wrapping_key=static_key,
        wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
    )

    raw_aes_keyring: IKeyring = mat_prov.create_raw_aes_keyring(
        input=keyring_input
    )

    # 6. Encrypt the data with the encryptionContext.
    # This is the important step in this example where we specify the algorithm suite
    # you want to use for encrypting your data
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        keyring=raw_aes_keyring,
        encryption_context=encryption_context,
        algorithm=AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    )

    # 7. Demonstrate that the ciphertext and plaintext are different.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert ciphertext != EXAMPLE_DATA, \
        "Ciphertext and plaintext data are the same. Invalid encryption"

    # 8. Decrypt your encrypted data using the same keyring you used on encrypt.
    plaintext_bytes, _ = client.decrypt(
        source=ciphertext,
        keyring=raw_aes_keyring,
        # Verify that the encryption context in the result contains the
        # encryption context supplied to the encryptData method
        encryption_context=encryption_context,
    )

    # 9. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
