from aws_encryption_sdk.materials_managers.mpl.materials import (
    EncryptionMaterialsFromMPL
)


class HalfSigningEncryptionMaterialsFromMPL(EncryptionMaterialsFromMPL):
    @EncryptionMaterialsFromMPL.algorithm.setter
    def algorithm(self, algorithm):
        self.set_algorithm = algorithm

    @EncryptionMaterialsFromMPL.algorithm.getter
    def algorithm(self):
        if hasattr(self, "set_algorithm"):
            return self.set_algorithm
        else:
            return self.algorithm
        
    @EncryptionMaterialsFromMPL.signing_key.setter
    def signing_key(self, signing_key):
        self.set_signing_key = signing_key

    @EncryptionMaterialsFromMPL.signing_key.getter
    def signing_key(self):
        if hasattr(self, "set_signing_key"):
            return self.set_signing_key
        else:
            return self.signing_key
