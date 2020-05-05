# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
The AWS Encryption SDK supports several different algorithm suites
that offer different security properties.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html

By default, the AWS Encryption SDK will let you use any of these,
but you might want to restrict that further.

We recommend that you use the default algorithm suite,
which uses AES-GCM with 256-bit keys, HKDF, and ECDSA message signing.
If your readers and writers have the same permissions,
you might want to omit the message signature for faster operation.
For more information about choosing a signed or unsigned algorithm suite,
see the AWS Encryption SDK developer guide:

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html#other-algorithms

This example shows how you can make a custom cryptographic materials manager (CMM)
that only allows encrypt requests that either specify one of these two algorithm suites
or do not specify an algorithm suite, in which case the default CMM uses the default algorithm suite.
"""
import aws_encryption_sdk
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers import (
    DecryptionMaterials,
    DecryptionMaterialsRequest,
    EncryptionMaterials,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager


class UnapprovedAlgorithmSuite(Exception):
    """Indicate that an unsupported algorithm suite was requested."""


class RequireApprovedAlgorithmSuitesCryptoMaterialsManager(CryptoMaterialsManager):
    """Only allow encryption requests for approved algorithm suites."""

    def __init__(self, keyring):
        # type: (Keyring) -> None
        """Set up the inner cryptographic materials manager using the provided keyring.

        :param Keyring keyring: Keyring to use in the inner cryptographic materials manager
        """
        self._allowed_algorithm_suites = {
            None,  # no algorithm suite in the request
            AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,  # the default algorithm suite
            AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,  # the recommended unsigned algorithm suite
        }
        # Wrap the provided keyring in the default cryptographic materials manager (CMM).
        #
        # This is the same thing that the encrypt and decrypt APIs, as well as the caching CMM,
        # do if you provide a keyring instead of a CMM.
        self._cmm = DefaultCryptoMaterialsManager(keyring=keyring)

    def get_encryption_materials(self, request):
        # type: (EncryptionMaterialsRequest) -> EncryptionMaterials
        """Block any requests that include an unapproved algorithm suite."""
        if request.algorithm not in self._allowed_algorithm_suites:
            raise UnapprovedAlgorithmSuite("Unapproved algorithm suite requested!")

        return self._cmm.get_encryption_materials(request)

    def decrypt_materials(self, request):
        # type: (DecryptionMaterialsRequest) -> DecryptionMaterials
        """Be more permissive on decrypt and just pass through."""
        return self._cmm.decrypt_materials(request)


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a custom cryptographic materials manager that filters requests.

    :param str aws_kms_cmk: The ARN of an AWS KMS CMK that protects data keys
    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    # Remember that your encryption context is NOT SECRET.
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the keyring that determines how your data keys are protected.
    keyring = AwsKmsKeyring(generator_key_id=aws_kms_cmk)

    # Create the algorithm suite restricting cryptographic materials manager using your keyring.
    cmm = RequireApprovedAlgorithmSuitesCryptoMaterialsManager(keyring=keyring)

    # Demonstrate that the algorithm suite restricting CMM will not let you use an unapproved algorithm suite.
    try:
        aws_encryption_sdk.encrypt(
            source=source_plaintext,
            encryption_context=encryption_context,
            materials_manager=cmm,
            algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16,
        )
    except UnapprovedAlgorithmSuite:
        # You asked for an unapproved algorithm suite.
        # Reaching this point means everything is working as expected.
        pass
    else:
        # The algorithm suite restricting CMM keeps this from happening.
        raise AssertionError("The algorithm suite restricting CMM does not let this happen!")

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
