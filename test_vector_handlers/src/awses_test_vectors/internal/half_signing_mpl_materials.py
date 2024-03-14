"""Allows overriding the algorithm and signing_key for EncryptionMaterialsFromMPL.
This must ONLY be used in testing and NOT in production..
This is used in testing malicious message modification (HalfSigningTampering).
"""
from aws_encryption_sdk.materials_managers.mpl.materials import (
    EncryptionMaterialsFromMPL
)


class HalfSigningEncryptionMaterialsFromMPL(EncryptionMaterialsFromMPL):
    """Allows overriding the algorithm and signing_key for EncryptionMaterialsFromMPL.
    This must ONLY be used in testing and NOT in production..
    This is used in testing malicious message modification (HalfSigningTampering).
    """
    # pylint thinks EncryptionMaterialsFromMPL.algorithm is a method
    # pylint: disable=invalid-overridden-method
    @EncryptionMaterialsFromMPL.algorithm.getter
    def algorithm(self):
        if hasattr(self, "set_algorithm"):
            return self.set_algorithm
        return self.algorithm

    @algorithm.setter
    def algorithm(self, algorithm):
        self.set_algorithm = algorithm

    # pylint thinks EncryptionMaterialsFromMPL.signing_key is a method
    # pylint: disable=invalid-overridden-method
    @EncryptionMaterialsFromMPL.signing_key.getter
    def signing_key(self):
        if hasattr(self, "set_signing_key"):
            return self.set_signing_key
        return self.signing_key

    @signing_key.setter
    def signing_key(self, signing_key):
        self.set_signing_key = signing_key
