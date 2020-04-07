# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
The AWS Encryption SDK supports several different algorithm suites
that offer different security properties.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html

By default, the AWS Encryption SDK will let you use any of these,
but you might want to restrict that further.
We do not recommend using the algorithm suites without key derivation,
so for this example we will show how to make a custom CMM
that will not allow you to use those algorithm suites.
"""
import aws_encryption_sdk
from aws_encryption_sdk.identifiers import AlgorithmSuite, KDFSuite
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers import (
    DecryptionMaterials,
    DecryptionMaterialsRequest,
    EncryptionMaterials,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager


class UnsupportedAlgorithmSuite(Exception):
    """Indicate that an unsupported algorithm suite was requested."""


class OnlyKdfAlgorithmSuitesCryptoMaterialsManager(CryptoMaterialsManager):
    """Only allow encryption requests for algorithm suites with a KDF."""

    def __init__(self, keyring):
        # type: (Keyring) -> None
        """Set up the inner cryptographic materials manager using the provided keyring.

        :param Keyring keyring: Keyring to use in the inner cryptographic materials manager
        """
        self._cmm = DefaultCryptoMaterialsManager(keyring=keyring)

    def get_encryption_materials(self, request):
        # type: (EncryptionMaterialsRequest) -> EncryptionMaterials
        """Block any requests that include an algorithm suite without a KDF."""
        if request.algorithm is not None and request.algorithm.kdf is KDFSuite.NONE:
            raise UnsupportedAlgorithmSuite("Non-KDF algorithm suites are not allowed!")

        return self._cmm.get_encryption_materials(request)

    def decrypt_materials(self, request):
        # type: (DecryptionMaterialsRequest) -> DecryptionMaterials
        """Be more permissive on decrypt and just pass through."""
        return self._cmm.decrypt_materials(request)


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a KMS keyring with a single CMK.

    :param str aws_kms_cmk: The ARN of an AWS KMS CMK that protects data keys
    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the keyring that determines how your data keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk)

    # Create the filtering cryptographic materials manager using your keyring.
    cmm = OnlyKdfAlgorithmSuitesCryptoMaterialsManager(keyring=keyring)

    # Demonstrate that the filtering CMM will not let you use non-KDF algorithm suites.
    try:
        aws_encryption_sdk.encrypt(
            source=source_plaintext,
            encryption_context=encryption_context,
            materials_manager=cmm,
            algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16,
        )
    except UnsupportedAlgorithmSuite:
        # You asked for a non-KDF algorithm suite.
        # Reaching this point means everything is working as expected.
        pass
    else:
        # The filtering CMM keeps this from happening.
        raise AssertionError("The filtering CMM does not let this happen!")

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, materials_manager=cmm
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same cryptographic materials manager you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, materials_manager=cmm)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
