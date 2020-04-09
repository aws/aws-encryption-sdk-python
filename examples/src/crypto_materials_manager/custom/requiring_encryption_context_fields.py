# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Encryption context is a powerful tool for access and audit controls
because it lets you tie *non-secret* metadata about a plaintext value to the encrypted message.
Within the AWS Encryption SDK,
you can use cryptographic materials managers to analyse the encryption context
to provide logical controls and additional metadata.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context

If you are using the AWS Encryption SDK with AWS KMS,
you can use AWS KMS to provide additional powerful controls using the encryption context.
For more information on that, see the KMS developer guide:

https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context

This example shows how to create a custom cryptographic materials manager (CMM)
that requires a particular field in the encryption context.
"""
import aws_encryption_sdk
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


class MissingClassificationError(Exception):
    """Indicates that an encryption context was found that lacked a classification identifier."""


class ClassificationRequiringCryptoMaterialsManager(CryptoMaterialsManager):
    """Only allow requests when the encryption context contains a classification identifier."""

    def __init__(self, keyring):
        # type: (Keyring) -> None
        """Set up the inner cryptographic materials manager using the provided keyring.

        :param Keyring keyring: Keyring to use in the inner cryptographic materials manager
        """
        self._classification_field = "classification"
        self._classification_error = MissingClassificationError("Encryption context does not contain classification!")
        # Wrap the provided keyring in the default cryptographic materials manager (CMM).
        #
        # This is the same thing that the encrypt and decrypt APIs, as well as the caching CMM,
        # do if you provide a keyring instead of a CMM.
        self._cmm = DefaultCryptoMaterialsManager(keyring=keyring)

    def get_encryption_materials(self, request):
        # type: (EncryptionMaterialsRequest) -> EncryptionMaterials
        """Block any requests that do not contain a classification identifier in the encryption context."""
        if self._classification_field not in request.encryption_context:
            raise self._classification_error

        return self._cmm.get_encryption_materials(request)

    def decrypt_materials(self, request):
        # type: (DecryptionMaterialsRequest) -> DecryptionMaterials
        """Block any requests that do not contain a classification identifier in the encryption context."""
        if self._classification_field not in request.encryption_context:
            raise self._classification_error

        return self._cmm.decrypt_materials(request)


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a custom cryptographic materials manager that filters requests.

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

    # Create the classification requiring cryptographic materials manager using your keyring.
    cmm = ClassificationRequiringCryptoMaterialsManager(keyring=keyring)

    # Demonstrate that the classification requiring CMM will not let you encrypt without a classification identifier.
    try:
        aws_encryption_sdk.encrypt(
            source=source_plaintext, encryption_context=encryption_context, materials_manager=cmm,
        )
    except MissingClassificationError:
        # Your encryption context did not contain a classification identifier.
        # Reaching this point means everything is working as expected.
        pass
    else:
        # The classification requiring CMM keeps this from happening.
        raise AssertionError("The classification requiring CMM does not let this happen!")

    # Encrypt your plaintext data.
    classified_ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext,
        encryption_context=dict(classification="secret", **encryption_context),
        materials_manager=cmm,
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert classified_ciphertext != source_plaintext

    # Decrypt your encrypted data using the same cryptographic materials manager you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=classified_ciphertext, materials_manager=cmm)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())

    # Now demonstrate the decrypt path of the classification requiring cryptographic materials manager.

    # Encrypt your plaintext using the keyring and do not include a classification identifier.
    unclassified_ciphertext, encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    )

    assert "classification" not in encrypt_header.encryption_context

    # Demonstrate that the classification requiring CMM
    # will not let you decrypt messages without classification identifiers.
    try:
        aws_encryption_sdk.decrypt(source=unclassified_ciphertext, materials_manager=cmm)
    except MissingClassificationError:
        # Your encryption context did not contain a classification identifier.
        # Reaching this point means everything is working as expected.
        pass
    else:
        # The classification requiring CMM keeps this from happening.
        raise AssertionError("The classification requiring CMM does not let this happen!")
