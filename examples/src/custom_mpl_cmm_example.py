# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example to create a custom implementation of the ESDK-MPL ICryptographicMaterialsManager class."""

from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateDefaultCryptographicMaterialsManagerInput,
    SignatureAlgorithmNone,
)
from aws_cryptographic_materialproviders.mpl.references import ICryptographicMaterialsManager, IKeyring

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy


# Custom CMM implementation using the MPL.
# This CMM only allows encryption/decryption using signing algorithms.
# It wraps an underlying CMM implementation and checks its materials
# to ensure that it is only using signed encryption algorithms.
class MPLCustomSigningSuiteOnlyCMM(ICryptographicMaterialsManager):
    """Example custom crypto materials manager class."""

    def __init__(self, keyring: IKeyring) -> None:
        """Constructor for MPLCustomSigningSuiteOnlyCMM class."""
        mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
            config=MaterialProvidersConfig()
        )

        # Create a CryptographicMaterialsManager for encryption and decryption
        cmm_input: CreateDefaultCryptographicMaterialsManagerInput = \
            CreateDefaultCryptographicMaterialsManagerInput(
                keyring=keyring
            )

        self.underlying_cmm: ICryptographicMaterialsManager = mat_prov.create_default_cryptographic_materials_manager(
            input=cmm_input
        )

    def get_encryption_materials(self, param):
        """Provides encryption materials appropriate for the request for the custom CMM.

        :param aws_cryptographic_materialproviders.mpl.models.GetEncryptionMaterialsInput param: Input object to
        provide to a crypto material manager's `get_encryption_materials` method.
        :returns: Encryption materials output
        :rtype: aws_cryptographic_materialproviders.mpl.models.GetEncryptionMaterialsOutput
        """
        materials = self.underlying_cmm.get_encryption_materials(param)
        if isinstance(materials.encryption_materials.algorithm_suite.signature, SignatureAlgorithmNone):
            raise ValueError(
                "Algorithm provided to MPLCustomSigningSuiteOnlyCMM"
                  + " is not a supported signing algorithm: " + str(materials.encryption_materials.algorithm_suite)
                  )
        return materials

    def decrypt_materials(self, param):
        """Provides decryption materials appropriate for the request for the custom CMM.

        :param aws_cryptographic_materialproviders.mpl.models.DecryptMaterialsInput param: Input object to provide
        to a crypto material manager's `decrypt_materials` method.
        :returns: Decryption materials output
        :rtype: aws_cryptographic_materialproviders.mpl.models.GetDecryptionMaterialsOutput
        """
        materials = self.underlying_cmm.decrypt_materials(param)
        if isinstance(materials.decryption_materials.algorithm_suite.signature, SignatureAlgorithmNone):
            raise ValueError(
                "Algorithm provided to MPLCustomSigningSuiteOnlyCMM"
                  + " is not a supported signing algorithm: " + str(materials.decryption_materials.algorithm_suite)
                  )
        return materials


EXAMPLE_DATA: bytes = b"Hello World"


def encrypt_decrypt_with_cmm(
    cmm: ICryptographicMaterialsManager
):
    """Encrypts and decrypts a string using a custom CMM.

    :param ICryptographicMaterialsManager cmm: CMM to use for encryption and decryption
    :param bytes source_plaintext: Data to encrypt
    """
    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Encrypt the plaintext source data
    ciphertext, encryptor_header = client.encrypt(
        source=EXAMPLE_DATA,
        materials_manager=cmm
    )

    # Decrypt the ciphertext
    cycled_plaintext, decrypted_header = client.decrypt(
        source=ciphertext,
        materials_manager=cmm
    )

    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source plaintext
    assert cycled_plaintext == EXAMPLE_DATA

    # Verify that the encryption context used in the decrypt operation includes all key pairs from
    # the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    #
    # In production, always use a meaningful encryption context. In this sample, we omit the
    # encryption context (no key pairs).
    # The encryptor_header.encryption_context has items of the form
    #     b'key': b'value'
    # We convert these to strings for easier comparison with the decrypted header below.
    for k, v in encryptor_header.encryption_context.items():
        k = str(k.decode("utf-8"))
        v = str(v.decode("utf-8"))
        assert v == decrypted_header.encryption_context[k], \
            "Encryption context does not match expected values"
