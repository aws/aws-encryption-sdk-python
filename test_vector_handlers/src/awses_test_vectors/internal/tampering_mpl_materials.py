"""Allows using ESDK-MPL interfaces with the tampering tests.
These must ONLY be used in testing and NOT in production.
"""
import attr
import six
from copy import copy


from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

# Ignore missing MPL for pylint, but the MPL is required for this class
# pylint: disable=import-error,no-name-in-module
from aws_encryption_sdk.materials_managers.mpl.materials import (
    EncryptionMaterialsFromMPL
)
from aws_encryption_sdk.materials_managers.mpl.cmm import (
    CryptoMaterialsManagerFromMPL
)
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateDefaultCryptographicMaterialsManagerInput,
)

try:
    from aws_encryption_sdk.identifiers import AlgorithmSuite
except ImportError:
    from aws_encryption_sdk.identifiers import Algorithm as AlgorithmSuite

class HalfSigningCryptoMaterialsManagerFromMPL(CryptoMaterialsManagerFromMPL):
    """
    Custom CMM that uses HalfSigningEncryptionMaterialsFromMPL.
    This extends CryptoMaterialsManagerFromMPL so ESDK-internal checks
    follow MPL logic.

    THIS IS ONLY USED TO CREATE INVALID MESSAGES and should never be used in
    production!
    """

    wrapped_default_cmm = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsManagerFromMPL))

    def __init__(self, master_key_provider):
        """Create a new CMM that wraps a the given CMM."""
        mpl = AwsCryptographicMaterialProviders(MaterialProvidersConfig())
        mpl_cmm = mpl.create_default_cryptographic_materials_manager(
            CreateDefaultCryptographicMaterialsManagerInput(
                keyring=master_key_provider
            )
        )
        self.wrapped_default_cmm = CryptoMaterialsManagerFromMPL(mpl_cmm=mpl_cmm)

    def get_encryption_materials(self, request):
        """
        Generate half-signing materials by requesting signing materials
        from the wrapped default CMM, and then changing the algorithm suite
        and removing the signing key from teh result.
        """
        if request.algorithm == AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
            signing_request = copy(request)
            signing_request.algorithm = AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384

            result = HalfSigningEncryptionMaterialsFromMPL(
                self.wrapped_default_cmm.get_encryption_materials(signing_request)
            )

            result.algorithm = request.algorithm
            result.signing_key = None

            return result

        raise NotImplementedError(
            "The half-sign tampering method is only supported on the "
            "AES_256_GCM_HKDF_SHA512_COMMIT_KEY algorithm suite."
        )

    def decrypt_materials(self, request):
        """Thunks to the wrapped default CMM"""
        return self.wrapped_default_cmm.decrypt_materials(request)


class HalfSigningEncryptionMaterialsFromMPL(EncryptionMaterialsFromMPL):
    """Allows overriding the algorithm and signing_key for EncryptionMaterialsFromMPL.
    This must ONLY be used in testing and NOT in production.
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


class ProviderInfoChangingCryptoMaterialsManagerFromMPL(CryptoMaterialsManagerFromMPL):
    """
    Custom CMM that modifies the provider info field on EDKs.
    This extends CryptoMaterialsManagerFromMPL so ESDK-internal checks
    follow MPL logic.

    THIS IS ONLY USED TO CREATE INVALID MESSAGES and should never be used in
    production!
    """

    wrapped_cmm = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsManager))
    new_provider_info = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __init__(self, materials_manager, new_provider_info):
        """Create a new CMM that wraps a the given CMM."""
        self.wrapped_cmm = materials_manager
        self.new_provider_info = new_provider_info

    def get_encryption_materials(self, request):
        """
        Request materials from the wrapped CMM, and then change the provider info
        on each EDK.
        """
        result = self.wrapped_cmm.get_encryption_materials(request)
        for encrypted_data_key in result.encrypted_data_keys:
            encrypted_data_key.key_provider.key_info = self.new_provider_info
        return result

    def decrypt_materials(self, request):
        """Thunks to the wrapped CMM"""
        return self.wrapped_cmm.decrypt_materials(request)
