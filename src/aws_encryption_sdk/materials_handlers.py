"""Provides encryption/decryption materials from an underlying materials provider."""
# These dependencies are only loaded if you install the MPL.
try:
    from aws_cryptographic_materialproviders.mpl.models import (
        DecryptionMaterials as MPL_DecryptionMaterials,
        EncryptedDataKey as MPL_EncryptedDataKey,
        EncryptionMaterials as MPL_EncryptionMaterials,
    )
except ImportError:
    pass

from typing import Dict, List, Set

from aws_encryption_sdk.identifiers import Algorithm, AlgorithmSuite
from aws_encryption_sdk.materials_managers import (
    DecryptionMaterials as Native_DecryptionMaterials,
    EncryptionMaterials as Native_EncryptionMaterials,
)
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey as Native_EncryptedDataKey, MasterKeyInfo


def _mpl_algorithm_id_to_native_algorithm_id(mpl_algorithm_id: str):
    # MPL algorithm suite ID == hex(native algorithm suite ID)
    return int(mpl_algorithm_id, 16)


class EncryptionMaterialsHandler:
    """
    In instances where encryption materials may be provided by either
    the native `aws_encryption_sdk.materials_managers.EncryptionMaterials`
    or the MPL's `aws_cryptographic_materialproviders.mpl.models.EncryptionMaterials`,
    this provides the correct materials based on the configured materials provider.
    """

    native_materials: Native_EncryptionMaterials
    mpl_materials: 'MPL_EncryptionMaterials'

    def __init__(
        self,
        materials: 'Native_EncryptionMaterials | MPL_EncryptionMaterials'
    ):
        """
        Create EncryptionMaterialsHandler.
        :param materials: Underlying encryption materials
        """
        if isinstance(materials, Native_EncryptionMaterials):
            self.native_materials = materials
        elif isinstance(materials, MPL_EncryptionMaterials):
            self.mpl_materials = materials
        else:
            raise ValueError(f"Invalid EncryptionMaterials passed to EncryptionMaterialsHandler.\
                               materials: {materials}")

    @property
    def algorithm(self) -> Algorithm:
        """Materials' native Algorithm."""
        if hasattr(self, "native_materials"):
            return self.native_materials.algorithm
        else:
            return AlgorithmSuite.get_by_id(
                _mpl_algorithm_id_to_native_algorithm_id(
                    self.mpl_materials.algorithm_suite.id.value
                )
            )

    @property
    def encryption_context(self) -> Dict[str, str]:
        """Materials' encryption context."""
        if hasattr(self, "native_materials"):
            return self.native_materials.encryption_context
        else:
            return self.mpl_materials.encryption_context

    @property
    def encrypted_data_keys(self) -> List[Native_EncryptedDataKey]:
        """Materials' encrypted data keys."""
        if hasattr(self, "native_materials"):
            return self.native_materials.encrypted_data_keys
        else:
            mpl_edk_list: List[MPL_EncryptedDataKey] = self.mpl_materials.encrypted_data_keys
            key_blob_list: Set[Native_EncryptedDataKey] = {Native_EncryptedDataKey(
                key_provider=MasterKeyInfo(
                    provider_id=mpl_edk.key_provider_id,
                    key_info=mpl_edk.key_provider_info,
                ),
                encrypted_data_key=mpl_edk.ciphertext,
            ) for mpl_edk in mpl_edk_list}
            return key_blob_list

    @property
    def data_encryption_key(self) -> DataKey:
        """Materials' data encryption key."""
        if hasattr(self, "native_materials"):
            return self.native_materials.data_encryption_key
        else:
            # TODO-MPL This impl is probably wrong, but works for for now
            # If this works for all features, great! Remove this comment before launch.
            # Otherwise, fix the implementation.
            mpl_dek = self.mpl_materials.plaintext_data_key
            return DataKey(
                # key_provider is unused, but the return type is DataKey
                key_provider=MasterKeyInfo(
                    provider_id="",
                    key_info=b''
                ),
                data_key=mpl_dek,
                encrypted_data_key=b'',  # No encrypted DEK
            )

    @property
    def signing_key(self) -> bytes:
        """Materials' signing key."""
        if hasattr(self, "native_materials"):
            return self.native_materials.signing_key
        else:
            return self.mpl_materials.signing_key


class DecryptionMaterialsHandler:
    """
    In instances where decryption materials may be provided by either
    the native `aws_encryption_sdk.materials_managers.DecryptionMaterials`
    or the MPL's `aws_cryptographic_materialproviders.mpl.models.DecryptionMaterials`,
    this provides the correct materials based on the configured materials provider.
    """

    native_materials: Native_DecryptionMaterials
    mpl_materials: 'MPL_DecryptionMaterials'

    def __init__(
        self,
        materials: 'Native_DecryptionMaterials | MPL_DecryptionMaterials'
    ):
        """
        Create DecryptionMaterialsHandler.
        :param materials: Underlying decryption materials
        """
        if isinstance(materials, Native_DecryptionMaterials):
            self.native_materials = materials
        elif isinstance(materials, MPL_DecryptionMaterials):
            self.mpl_materials = materials
        else:
            raise ValueError(f"Invalid DecryptionMaterials passed to DecryptionMaterialsHandler.\
                               materials: {materials}")

    @property
    def data_key(self) -> DataKey:
        """Materials' data key."""
        if hasattr(self, "native_materials"):
            return self.native_materials.data_key
        else:
            # TODO-MPL This impl is probably wrong, but works for for now
            # If this works for all features, great! Remove this comment before launch.
            # Otherwise, fix the implementation.
            return DataKey(
                key_provider=MasterKeyInfo(
                    provider_id="",
                    key_info=b''
                ),
                data_key=self.mpl_materials.plaintext_data_key,
                encrypted_data_key=b'',
            )

    @property
    def verification_key(self) -> bytes:
        """Materials' verification key."""
        if hasattr(self, "native_materials"):
            return self.native_materials.verification_key
        else:
            return self.mpl_materials.verification_key
