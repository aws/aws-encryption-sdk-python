# These dependencies are only loaded if you install the MPL.
try:
    from aws_cryptographic_materialproviders.mpl.errors import (
        AwsCryptographicMaterialProvidersException
    )
    from aws_cryptographic_materialproviders.mpl.references import (
        ICryptographicMaterialsManager,
    )
    from aws_cryptographic_materialproviders.mpl.models import (
        GetEncryptionMaterialsInput,
        GetEncryptionMaterialsOutput,
        DecryptMaterialsInput,
        DecryptMaterialsOutput,
        EncryptedDataKey as MPL_EncryptedDataKey,
        CommitmentPolicyESDK,
        AlgorithmSuiteIdESDK,
    )
except ImportError:
    pass

from aws_encryption_sdk.exceptions import (
    AWSEncryptionSDKClientError,
)
from aws_encryption_sdk.materials_managers import (
    DecryptionMaterialsRequest,
    EncryptionMaterialsRequest,
)
from aws_encryption_sdk.materials_managers.base import (
    CryptoMaterialsManager,
)
from aws_encryption_sdk.materials_handlers import (
    EncryptionMaterialsHandler,
    DecryptionMaterialsHandler,
)
from aws_encryption_sdk.structures import (
    EncryptedDataKey as Native_EncryptedDataKey,
)
from aws_encryption_sdk.identifiers import (
    CommitmentPolicy,
)


# TODO-MPL Should this implement interface..? seems like yes since it implements all of interface methods
class CMMHandler(CryptoMaterialsManager):
    native_cmm: CryptoMaterialsManager
    mpl_cmm: 'ICryptographicMaterialsManager'

    def _is_using_native_cmm(self):
        return hasattr(self, "native_cmm") and not hasattr(self, "mpl_cmm")

    def __init__(
        self,
        cmm: 'CryptoMaterialsManager | ICryptographicMaterialsManager'
    ):
        if isinstance(cmm, CryptoMaterialsManager):
            self.native_cmm = cmm
        elif isinstance(cmm, ICryptographicMaterialsManager):
            self.mpl_cmm = cmm
        else:
            raise ValueError(f"Invalid CMM passed to CMMHander: {cmm=}")

    def get_encryption_materials(
        self,
        request: EncryptionMaterialsRequest
    ) -> EncryptionMaterialsHandler:
        '''
        Returns an EncryptionMaterialsHandler for the configured CMM.
        '''
        if (self._is_using_native_cmm()):
            return EncryptionMaterialsHandler(self.native_cmm.get_encryption_materials(request))
        else:
            try:
                input: GetEncryptionMaterialsInput = CMMHandler._create_mpl_get_encryption_materials_input_from_request(
                    request
                )
                output: GetEncryptionMaterialsOutput = self.mpl_cmm.get_encryption_materials(input)
                return EncryptionMaterialsHandler(output.encryption_materials)
            except AwsCryptographicMaterialProvidersException as e:
                # Wrap MPL error into the ESDK error type
                # so customers only have to catch ESDK error types.
                raise AWSEncryptionSDKClientError(e)

    @staticmethod
    def _create_mpl_get_encryption_materials_input_from_request(
        request: EncryptionMaterialsRequest
    ) -> 'GetEncryptionMaterialsInput':
        output: GetEncryptionMaterialsInput = GetEncryptionMaterialsInput(
            encryption_context=request.encryption_context,
            commitment_policy=CMMHandler._map_native_commitment_policy_to_mpl_commitment_policy(
                request.commitment_policy
            ),
            # TODO double check this
            # optional... maybe this needs to be kwargs??
            # algorithm_suite_id=request.algorithm.algorithm_id,
            max_plaintext_length=request.plaintext_length,
        )
        return output

    @staticmethod
    def _map_native_commitment_policy_to_mpl_commitment_policy(
        native_commitment_policy: CommitmentPolicy
    ) -> CommitmentPolicyESDK:
        if native_commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT:
            return CommitmentPolicyESDK(value="FORBID_ENCRYPT_ALLOW_DECRYPT")
        elif native_commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT:
            return CommitmentPolicyESDK(value="REQUIRE_ENCRYPT_ALLOW_DECRYPT")
        elif native_commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
            return CommitmentPolicyESDK(value="REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
        else:
            raise ValueError(f"Invalid {native_commitment_policy=}")

    def decrypt_materials(
        self,
        request: DecryptionMaterialsRequest
    ) -> DecryptionMaterialsHandler:
        '''
        Returns a DecryptionMaterialsHandler for the configured CMM.
        '''
        if (self._is_using_native_cmm()):
            return DecryptionMaterialsHandler(self.native_cmm.decrypt_materials(request))
        else:
            try:
                input: 'DecryptMaterialsInput' = CMMHandler._create_mpl_decrypt_materials_input_from_request(request)
                output: 'DecryptMaterialsOutput' = self.mpl_cmm.decrypt_materials(input)
                return DecryptionMaterialsHandler(output.decryption_materials)
            except AwsCryptographicMaterialProvidersException as e:
                # Wrap MPL error into the ESDK error type
                # so customers only have to catch ESDK error types.
                raise AWSEncryptionSDKClientError(e)

    @staticmethod
    def _native_algorithm_id_to_mpl_algorithm_id(native_algorithm_id: str) -> AlgorithmSuiteIdESDK:
        # MPL algorithm suite ID = hexstr(native_algorithm_id) padded to 4 digits post-`x`.
        return AlgorithmSuiteIdESDK(f"{native_algorithm_id:#0{6}x}")

    @staticmethod
    def _create_mpl_decrypt_materials_input_from_request(
        request: DecryptionMaterialsRequest
    ) -> 'DecryptMaterialsInput':
        key_blob_list: list[Native_EncryptedDataKey] = request.encrypted_data_keys
        list_edks = [MPL_EncryptedDataKey(
            key_provider_id=key_blob.key_provider.provider_id,
            key_provider_info=key_blob.key_provider.key_info,
            ciphertext=key_blob.encrypted_data_key,
        ) for key_blob in key_blob_list]
        output: DecryptMaterialsInput = DecryptMaterialsInput(
            algorithm_suite_id=CMMHandler._native_algorithm_id_to_mpl_algorithm_id(
                request.algorithm.algorithm_id
            ),
            commitment_policy=CMMHandler._map_native_commitment_policy_to_mpl_commitment_policy(
                request.commitment_policy
            ),
            encrypted_data_keys=list_edks,
            encryption_context=request.encryption_context,
        )
        return output
