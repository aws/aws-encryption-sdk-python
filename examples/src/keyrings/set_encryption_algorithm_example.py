# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
This example demonstrates how to set an encryption algorithm while using the Raw AES Keyring
in the AWS Encryption SDK.

Encryption algorithms can be set in a similar manner in other keyrings as well. However,
please make sure that you're using a logical encryption algorithm that is compatible with your
keyring. For example, AWS KMS RSA Keyring does not support use with an algorithm suite
containing an asymmetric signature.

The Raw AES keyring encrypts data by using the AES-GCM algorithm and a wrapping key that
you specify as a byte array. You can specify only one wrapping key in each Raw AES keyring,
but you can include multiple Raw AES keyrings, alone or with other keyrings, in a multi-keyring.

The AES wrapping algorithm (AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16) protects your data key using
the user-provided wrapping key. The encryption algorithm used in the encrypt() method for a Raw
AES keyring is the algorithm used to protect your data using the data key. This example
demonstrates setting the latter, which is the encryption algorithm for protecting your data.
The default algorithm used in encrypt method is AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
which is a committing and signing algorithm. This example sets the encryption algorithm as
AES_256_GCM_HKDF_SHA512_COMMIT_KEY which is a committing but non-signing algorithm.

This example creates a Raw AES Keyring and then encrypts a custom input EXAMPLE_DATA
with an encryption context and the encryption algorithm AES_256_GCM_HKDF_SHA512_COMMIT_KEY.
This example also includes some sanity checks for demonstration:
1. Ciphertext and plaintext data are not the same
2. Encryption context is correct in the decrypted message header
3. Decrypted plaintext value matches EXAMPLE_DATA
These sanity checks are for demonstration in the example only. You do not need these in your code.

For more information on how to use Raw AES keyrings, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-raw-aes-keyring.html
"""
import secrets
import sys

from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import AesWrappingAlg, CreateRawAesKeyringInput
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from typing import Dict

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.identifiers import AlgorithmSuite

# TODO-MPL: Remove this as part of removing PYTHONPATH hacks.
MODULE_ROOT_DIR = '/'.join(__file__.split("/")[:-1])

sys.path.append(MODULE_ROOT_DIR)

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
    # Specify the encryption algorithm you want to use for encrypting your data here
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
    plaintext_bytes, dec_header = client.decrypt(
        source=ciphertext,
        keyring=raw_aes_keyring
    )

    # 9. Demonstrate that the encryption context is correct in the decrypted message header
    # (This is an example for demonstration; you do not need to do this in your own code.)
    for k, v in encryption_context.items():
        assert v == dec_header.encryption_context[k], \
            "Encryption context does not match expected values"

    # 10. Demonstrate that the decrypted plaintext is identical to the original plaintext.
    # (This is an example for demonstration; you do not need to do this in your own code.)
    assert plaintext_bytes == EXAMPLE_DATA, \
        "Decrypted plaintext should be identical to the original plaintext. Invalid decryption"
