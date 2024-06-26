# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Example to create a custom implementation of the MPL's ICryptographicMaterialsManager class and use it with the ESDK.

The cryptographic materials manager (CMM) assembles the cryptographic materials that are used
to encrypt and decrypt data. The cryptographic materials include plaintext and encrypted data keys,
and an optional message signing key.

Cryptographic Materials Managers (CMMs) are composable; if you just want to extend the behavior of
the default CMM, you can do this as demonstrated in this example. This is the easiest approach if
you are just adding a small check to the CMM methods, as in this example.

If your use case calls for fundamentally changing aspects of the default CMM, you can also write
your own implementation without extending an existing CMM. The default CMM's implementation is a
good reference to use if you need to write a custom CMM implementation from scratch.
Custom implementations of CMMs must implement get_encryption_materials and decrypt_materials.

For more information on a default implementation of a CMM,
please look at the default_cryptographic_materials_manager_example.py example.

For more information on Cryptographic Material Managers, see
https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#crypt-materials-manager
"""

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

    def __init__(self, keyring: IKeyring, cmm: ICryptographicMaterialsManager = None) -> None:
        """Constructor for MPLCustomSigningSuiteOnlyCMM class."""
        if cmm is not None:
            self.underlying_cmm = cmm
        else:
            mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
                config=MaterialProvidersConfig()
            )

            # Create a CryptographicMaterialsManager for encryption and decryption
            cmm_input: CreateDefaultCryptographicMaterialsManagerInput = \
                CreateDefaultCryptographicMaterialsManagerInput(
                    keyring=keyring
                )

            self.underlying_cmm: ICryptographicMaterialsManager = \
                mat_prov.create_default_cryptographic_materials_manager(
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
    """
    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Encrypt the plaintext source data
    ciphertext, _ = client.encrypt(
        source=EXAMPLE_DATA,
        materials_manager=cmm
    )

    # Decrypt the ciphertext
    cycled_plaintext, _ = client.decrypt(
        source=ciphertext,
        materials_manager=cmm
    )

    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source plaintext
    assert cycled_plaintext == EXAMPLE_DATA
