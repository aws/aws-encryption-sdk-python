# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Retrieves encryption/decryption materials from the MPL and interfaces them to EDK components.

The aws-cryptographic-materials-library MUST be installed to use this module.
"""
# pylint should pass even if the MPL isn't installed
# Also thinks these imports aren't used if it can't import them
# noqa pylint: disable=import-error,unused-import
from aws_cryptographic_materialproviders.mpl.errors import AwsCryptographicMaterialProvidersException
from aws_cryptographic_materialproviders.mpl.models import (
    AlgorithmSuiteIdESDK as MPL_AlgorithmSuiteIdESDK,
    CommitmentPolicyESDK as MPL_CommitmentPolicyESDK,
    DecryptMaterialsInput as MPL_DecryptMaterialsInput,
    DecryptMaterialsOutput as MPL_DecryptMaterialsOutput,
    EncryptedDataKey as MPL_EncryptedDataKey,
    GetEncryptionMaterialsInput as MPL_GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput as MPL_GetEncryptionMaterialsOutput,
)
from aws_cryptographic_materialproviders.mpl.references import (
    ICryptographicMaterialsManager as MPL_ICryptographicMaterialsManager,
)
# noqa pylint: enable=import-error,unused-import
# pylint and isort disagree on where this should go. Choose isort and disable pylint for this.
from typing import List  # noqa pylint: disable=wrong-import-order

from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.identifiers import CommitmentPolicy
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.mpl.materials import DecryptionMaterialsFromMPL, EncryptionMaterialsFromMPL
from aws_encryption_sdk.structures import EncryptedDataKey as Native_EncryptedDataKey


class CryptoMaterialsManagerFromMPL(CryptoMaterialsManager):
    """
    In instances where encryption materials are provided by an implementation of the MPL's
    `aws_cryptographic_materialproviders.mpl.references.MPL_ICryptographicMaterialsManager`,
    this maps the ESDK-Python CMM interfaces to the MPL CMM.
    """

    mpl_cmm: 'MPL_ICryptographicMaterialsManager'

    def __init__(
        self,
        mpl_cmm: 'MPL_ICryptographicMaterialsManager'
    ):
        """
        Create CryptoMaterialsManagerFromMPL.
        :param mpl_cmm: Underlying MPL cryptographic materials manager
        """
        if isinstance(mpl_cmm, MPL_ICryptographicMaterialsManager):
            self.mpl_cmm = mpl_cmm
        else:
            raise ValueError(f"Invalid CMM passed to CryptoMaterialsManagerFromMPL. cmm: {mpl_cmm}")

    def get_encryption_materials(
        self,
        request: EncryptionMaterialsRequest
    ) -> EncryptionMaterialsFromMPL:
        """
        Returns an EncryptionMaterialsHandler for the configured CMM.
        :param request: Request for encryption materials
        """
        try:
            mpl_input: MPL_GetEncryptionMaterialsInput = \
                CryptoMaterialsManagerFromMPL._native_to_mpl_get_encryption_materials(
                    request
                )
            mpl_output: MPL_GetEncryptionMaterialsOutput = self.mpl_cmm.get_encryption_materials(mpl_input)
            return EncryptionMaterialsFromMPL(mpl_output.encryption_materials)
        except AwsCryptographicMaterialProvidersException as mpl_exception:
            # Wrap MPL error into the ESDK error type
            # so customers only have to catch ESDK error types.
            raise AWSEncryptionSDKClientError(mpl_exception)

    @staticmethod
    def _native_to_mpl_get_encryption_materials(
        request: EncryptionMaterialsRequest
    ) -> 'MPL_GetEncryptionMaterialsInput':
        commitment_policy = CryptoMaterialsManagerFromMPL._native_to_mpl_commitment_policy(
            request.commitment_policy
        )
        output: MPL_GetEncryptionMaterialsInput = MPL_GetEncryptionMaterialsInput(
            encryption_context=request.encryption_context,
            commitment_policy=commitment_policy,
            algorithm_suite_id=CryptoMaterialsManagerFromMPL._native_algorithm_id_to_mpl_algorithm_id(
                request.algorithm.algorithm_id
            ),
            max_plaintext_length=request.plaintext_length,
        )
        return output

    @staticmethod
    def _native_to_mpl_commitment_policy(
        native_commitment_policy: CommitmentPolicy
    ) -> 'MPL_CommitmentPolicyESDK':
        if native_commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT:
            return MPL_CommitmentPolicyESDK(value="FORBID_ENCRYPT_ALLOW_DECRYPT")
        elif native_commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT:
            return MPL_CommitmentPolicyESDK(value="REQUIRE_ENCRYPT_ALLOW_DECRYPT")
        elif native_commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
            return MPL_CommitmentPolicyESDK(value="REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
        else:
            raise ValueError(f"Invalid native_commitment_policy: {native_commitment_policy}")

    def decrypt_materials(
        self,
        request: DecryptionMaterialsRequest
    ) -> DecryptionMaterialsFromMPL:
        """
        Returns a DecryptionMaterialsFromMPL for the configured CMM.
        :param request: Request for decryption materials
        """
        try:
            mpl_input: 'MPL_DecryptMaterialsInput' = \
                CryptoMaterialsManagerFromMPL._create_mpl_decrypt_materials_input_from_request(request)
            mpl_output: 'MPL_DecryptMaterialsOutput' = self.mpl_cmm.decrypt_materials(mpl_input)
            return DecryptionMaterialsFromMPL(mpl_output.decryption_materials)
        except AwsCryptographicMaterialProvidersException as mpl_exception:
            # Wrap MPL error into the ESDK error type
            # so customers only have to catch ESDK error types.
            raise AWSEncryptionSDKClientError(mpl_exception)

    @staticmethod
    def _native_algorithm_id_to_mpl_algorithm_id(native_algorithm_id: str) -> 'MPL_AlgorithmSuiteIdESDK':
        # MPL algorithm suite ID = hexstr(native_algorithm_id) padded to 4 digits post-`x`.
        return MPL_AlgorithmSuiteIdESDK(f"{native_algorithm_id:#0{6}x}")

    @staticmethod
    def _create_mpl_decrypt_materials_input_from_request(
        request: DecryptionMaterialsRequest
    ) -> 'MPL_DecryptMaterialsInput':
        key_blob_list: List[Native_EncryptedDataKey] = request.encrypted_data_keys
        list_edks = [MPL_EncryptedDataKey(
            key_provider_id=key_blob.key_provider.provider_id,
            key_provider_info=key_blob.key_provider.key_info,
            ciphertext=key_blob.encrypted_data_key,
        ) for key_blob in key_blob_list]
        output: MPL_DecryptMaterialsInput = MPL_DecryptMaterialsInput(
            algorithm_suite_id=CryptoMaterialsManagerFromMPL._native_algorithm_id_to_mpl_algorithm_id(
                request.algorithm.algorithm_id
            ),
            commitment_policy=CryptoMaterialsManagerFromMPL._native_to_mpl_commitment_policy(
                request.commitment_policy
            ),
            encrypted_data_keys=list_edks,
            encryption_context=request.encryption_context,
            reproduced_encryption_context=request.reproduced_encryption_context,
        )
        return output
