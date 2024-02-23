"""Retrieves encryption/decryption materials from the MPL."""

# These dependencies are only loaded if you install the MPL.
try:
    # pylint seems to struggle with this conditional import
    # pylint: disable=unused-import
    from aws_cryptographic_materialproviders.mpl.errors import AwsCryptographicMaterialProvidersException
    from aws_cryptographic_materialproviders.mpl.models import (
        AlgorithmSuiteIdESDK,
        CommitmentPolicyESDK,
        DecryptMaterialsInput,
        DecryptMaterialsOutput,
        EncryptedDataKey as MPL_EncryptedDataKey,
        GetEncryptionMaterialsInput,
        GetEncryptionMaterialsOutput,
    )
    from aws_cryptographic_materialproviders.mpl.references import ICryptographicMaterialsManager
    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False

from typing import List

from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.identifiers import CommitmentPolicy
from aws_encryption_sdk.materials_managers.mpl.materials import MPLEncryptionMaterials, MPLDecryptionMaterials
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.structures import EncryptedDataKey as Native_EncryptedDataKey


class MPLCMMHandler(CryptoMaterialsManager):
    """
    In instances where encryption materials are provided by an implementation of the MPL's
    `aws_cryptographic_materialproviders.mpl.references.ICryptographicMaterialsManager`,
    this maps the ESDK CMM interfaces to the MPL CMM.
    """

    mpl_cmm: 'ICryptographicMaterialsManager'

    def __init__(
        self,
        mpl_cmm: 'ICryptographicMaterialsManager'
    ):
        """
        Create MPLCMMHandler.
        :param mpl_cmm: Underlying MPL cryptographic materials manager
        """
        if not _HAS_MPL:
            raise ImportError("You MUST install the aws-cryptographic-material-providers "
                              f"library to create an instance of {MPLCMMHandler}")
        if isinstance(mpl_cmm, ICryptographicMaterialsManager):
            self.mpl_cmm = mpl_cmm
        else:
            raise ValueError(f"Invalid CMM passed to MPLCMMHandler. cmm: {mpl_cmm}")

    def get_encryption_materials(
        self,
        request: EncryptionMaterialsRequest
    ) -> MPLEncryptionMaterials:
        """
        Returns an EncryptionMaterialsHandler for the configured CMM.
        :param request: Request for encryption materials
        """
        try:
            mpl_input: GetEncryptionMaterialsInput = MPLCMMHandler._native_to_mpl_get_encryption_materials(
                request
            )
            mpl_output: GetEncryptionMaterialsOutput = self.mpl_cmm.get_encryption_materials(mpl_input)
            return MPLEncryptionMaterials(mpl_output.encryption_materials)
        except AwsCryptographicMaterialProvidersException as mpl_exception:
            # Wrap MPL error into the ESDK error type
            # so customers only have to catch ESDK error types.
            raise AWSEncryptionSDKClientError(mpl_exception)

    @staticmethod
    def _native_to_mpl_get_encryption_materials(
        request: EncryptionMaterialsRequest
    ) -> 'GetEncryptionMaterialsInput':
        commitment_policy = MPLCMMHandler._native_to_mpl_commmitment_policy(
            request.commitment_policy
        )
        output: GetEncryptionMaterialsInput = GetEncryptionMaterialsInput(
            encryption_context=request.encryption_context,
            commitment_policy=commitment_policy,
            max_plaintext_length=request.plaintext_length,
        )
        return output

    @staticmethod
    def _native_to_mpl_commmitment_policy(
        native_commitment_policy: CommitmentPolicy
    ) -> 'CommitmentPolicyESDK':
        if native_commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT:
            return CommitmentPolicyESDK(value="FORBID_ENCRYPT_ALLOW_DECRYPT")
        elif native_commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT:
            return CommitmentPolicyESDK(value="REQUIRE_ENCRYPT_ALLOW_DECRYPT")
        elif native_commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
            return CommitmentPolicyESDK(value="REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
        else:
            raise ValueError(f"Invalid native_commitment_policy: {native_commitment_policy}")

    def decrypt_materials(
        self,
        request: DecryptionMaterialsRequest
    ) -> MPLDecryptionMaterials:
        """
        Returns a MPLDecryptionMaterials for the configured CMM.
        :param request: Request for decryption materials
        """
        try:
            mpl_input: 'DecryptMaterialsInput' = \
                MPLCMMHandler._create_mpl_decrypt_materials_input_from_request(request)
            mpl_output: 'DecryptMaterialsOutput' = self.mpl_cmm.decrypt_materials(mpl_input)
            return MPLDecryptionMaterials(mpl_output.decryption_materials)
        except AwsCryptographicMaterialProvidersException as mpl_exception:
            # Wrap MPL error into the ESDK error type
            # so customers only have to catch ESDK error types.
            raise AWSEncryptionSDKClientError(mpl_exception)

    @staticmethod
    def _native_algorithm_id_to_mpl_algorithm_id(native_algorithm_id: str) -> 'AlgorithmSuiteIdESDK':
        # MPL algorithm suite ID = hexstr(native_algorithm_id) padded to 4 digits post-`x`.
        return AlgorithmSuiteIdESDK(f"{native_algorithm_id:#0{6}x}")

    @staticmethod
    def _create_mpl_decrypt_materials_input_from_request(
        request: DecryptionMaterialsRequest
    ) -> 'DecryptMaterialsInput':
        key_blob_list: List[Native_EncryptedDataKey] = request.encrypted_data_keys
        list_edks = [MPL_EncryptedDataKey(
            key_provider_id=key_blob.key_provider.provider_id,
            key_provider_info=key_blob.key_provider.key_info,
            ciphertext=key_blob.encrypted_data_key,
        ) for key_blob in key_blob_list]
        output: DecryptMaterialsInput = DecryptMaterialsInput(
            algorithm_suite_id=MPLCMMHandler._native_algorithm_id_to_mpl_algorithm_id(
                request.algorithm.algorithm_id
            ),
            commitment_policy=MPLCMMHandler._native_to_mpl_commmitment_policy(
                request.commitment_policy
            ),
            encrypted_data_keys=list_edks,
            encryption_context=request.encryption_context,
        )
        return output
