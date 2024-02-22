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


def _mpl_algorithm_id_to_native_algorithm_id(mpl_algorithm_id: str) -> int:
    # MPL algorithm suite ID == hex(native algorithm suite ID)
    return int(mpl_algorithm_id, 16)


class MPLEncryptionMaterials(Native_EncryptionMaterials):
    """
    In instances where encryption materials are be provided by
    the MPL's `aws_cryptographic_materialproviders.mpl.models.EncryptionMaterials`,
    this maps the ESDK interfaces to the underlying MPL materials.
    """

    mpl_materials: 'MPL_EncryptionMaterials'

    def __init__(
        self,
        materials: 'MPL_EncryptionMaterials'
    ):
        """
        Create MPLEncryptionMaterialsHandler.
        :param materials: Underlying encryption materials
        """
        if isinstance(materials, MPL_EncryptionMaterials):
            self.mpl_materials = materials
        else:
            raise ValueError("Invalid EncryptionMaterials passed to EncryptionMaterialsHandler. "
                             f"materials: {materials}")

    @property
    def algorithm(self) -> Algorithm:
        """Materials' native Algorithm."""
        return AlgorithmSuite.get_by_id(
            _mpl_algorithm_id_to_native_algorithm_id(
                self.mpl_materials.algorithm_suite.id.value
            )
        )

    @property
    def encryption_context(self) -> Dict[str, str]:
        """Materials' encryption context."""
        return self.mpl_materials.encryption_context

    @property
    def encrypted_data_keys(self) -> List[Native_EncryptedDataKey]:
        """Materials' encrypted data keys."""
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
        return self.mpl_materials.signing_key


class MPLDecryptionMaterials(Native_DecryptionMaterials):
    """
    In instances where decryption materials are be provided by
    the MPL's `aws_cryptographic_materialproviders.mpl.models.DecryptionMaterials`,
    this maps the ESDK interfaces to the underlying MPL materials.
    """

    mpl_materials: 'MPL_DecryptionMaterials'

    def __init__(
        self,
        materials: 'MPL_DecryptionMaterials'
    ):
        """
        Create DecryptionMaterialsHandler.
        :param materials: Underlying decryption materials
        """
        if isinstance(materials, MPL_DecryptionMaterials):
            self.mpl_materials = materials
        else:
            raise ValueError(f"Invalid DecryptionMaterials passed to DecryptionMaterialsHandler.\
                               materials: {materials}")

    @property
    def data_key(self) -> DataKey:
        """Materials' data key."""
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
        return self.mpl_materials.verification_key
