"""Allows overriding the algorithm and signing_key for EncryptionMaterialsFromMPL.
This must ONLY be used in testing and NOT in production..
This is used in testing malicious message modification (HalfSigningTampering).
"""
# Ignore missing MPL for pylint, but the MPL is required for this class
# pylint: disable=import-error,no-name-in-module
from aws_encryption_sdk.materials_managers.mpl.materials import (
    EncryptionMaterialsFromMPL
)


class HalfSigningEncryptionMaterialsFromMPL(EncryptionMaterialsFromMPL):
    """Allows overriding the algorithm and signing_key for EncryptionMaterialsFromMPL.
    This must ONLY be used in testing and NOT in production..
    This is used in testing malicious message modification (HalfSigningTampering).
    """

    _underlying_materials: EncryptionMaterialsFromMPL

    def __init__(self, underling_materials):
        self._underlying_materials = underling_materials

    # pylint thinks EncryptionMaterialsFromMPL.algorithm is a method
    # pylint: disable=invalid-overridden-method
    @property
    def algorithm(self):
        """Return any previously-provided overriden algorithm;
        if none was provided, returns underlying algorithm from encryption materials.
        """
        if hasattr(self, "set_algorithm"):
            return self.set_algorithm
        return self._underlying_materials.algorithm

    @algorithm.setter
    def algorithm(self, algorithm):
        self.set_algorithm = algorithm

    # pylint thinks EncryptionMaterialsFromMPL.signing_key is a method
    # pylint: disable=invalid-overridden-method
    @property
    def signing_key(self):
        """Return any previously-provided overriden signing_key;
        if none was provided, returns underlying signing_key from encryption materials.
        """
        if hasattr(self, "set_signing_key"):
            return self.set_signing_key
        return self._underlying_materials.algorithm

    @signing_key.setter
    def signing_key(self, signing_key):
        self.set_signing_key = signing_key

    @property
    def encryption_context(self):
        return self._underlying_materials.encryption_context

    @property
    def encrypted_data_keys(self):
        return self._underlying_materials.encrypted_data_keys
    
    @property
    def data_encryption_key(self):
        return self._underlying_materials.data_encryption_key
    
    @property
    def required_encryption_context_keys(self):
        return self._underlying_materials.required_encryption_context_keys
