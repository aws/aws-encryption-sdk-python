# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example to create a custom implementation of the native ESDK CryptoMaterialsManager class."""

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy, StrictAwsKmsMasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager


# Custom CMM implementation.
# This CMM only allows encryption/decryption using signing algorithms.
# It wraps an underlying CMM implementation and checks its materials
# to ensure that it is only using signed encryption algorithms.
class CustomSigningSuiteOnlyCMM(CryptoMaterialsManager):
    """Example custom crypto materials manager class."""

    def __init__(self, master_key_provider: StrictAwsKmsMasterKeyProvider) -> None:
        """Constructor for CustomSigningSuiteOnlyCMM class."""
        self.underlying_cmm = DefaultCryptoMaterialsManager(master_key_provider)

    def get_encryption_materials(self, request):
        """Provides encryption materials appropriate for the request for the custom CMM.

        :param EncryptionMaterialsRequest request: Request object to provide to a
        crypto material manager's `get_encryption_materials` method.
        :returns: Encryption materials
        :rtype: EncryptionMaterials
        """
        materials = self.underlying_cmm.get_encryption_materials(request)
        if not materials.algorithm.is_signing():
            raise ValueError(
                "Algorithm provided to CustomSigningSuiteOnlyCMM"
                  + " is not a supported signing algorithm: " + materials.algorithm
                  )
        return materials

    def decrypt_materials(self, request):
        """Provides decryption materials appropriate for the request for the custom CMM.

        :param DecryptionMaterialsRequest request: Request object to provide to a
        crypto material manager's `decrypt_materials` method.
        """
        if not request.algorithm.is_signing():
            raise ValueError(
                "Algorithm provided to CustomSigningSuiteOnlyCMM"
                  + " is not a supported signing algorithm: " + request.algorithm
                  )
        return self.underlying_cmm.decrypt_materials(request)


def encrypt_decrypt_with_cmm(
    cmm: CryptoMaterialsManager,
    source_plaintext: str
):
    """Encrypts and decrypts a string using a custom CMM.

    :param CryptoMaterialsManager cmm: CMM to use for encryption and decryption
    :param bytes source_plaintext: Data to encrypt
    """
    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Encrypt the plaintext source data
    ciphertext, encryptor_header = client.encrypt(
        source=source_plaintext,
        materials_manager=cmm
    )

    # Decrypt the ciphertext
    cycled_plaintext, decrypted_header = client.decrypt(
        source=ciphertext,
        materials_manager=cmm
    )

    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source plaintext
    assert cycled_plaintext == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes all key pairs from
    # the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    #
    # In production, always use a meaningful encryption context. In this sample, we omit the
    # encryption context (no key pairs).
    assert all(
        pair in decrypted_header.encryption_context.items() for pair in encryptor_header.encryption_context.items()
    )
