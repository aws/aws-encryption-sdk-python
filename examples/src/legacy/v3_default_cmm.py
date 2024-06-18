# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Default crypto material manager class example for ESDK V3."""
import logging

import attr

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import MasterKeyProviderError, SerializationError
from aws_encryption_sdk.identifiers import CommitmentPolicy
from aws_encryption_sdk.internal.crypto.authentication import Signer, Verifier
from aws_encryption_sdk.internal.crypto.elliptic_curve import generate_ecc_signing_key
from aws_encryption_sdk.internal.defaults import ALGORITHM, ALGORITHM_COMMIT_KEY, ENCODED_SIGNER_KEY
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.internal.utils import prepare_data_keys
from aws_encryption_sdk.internal.utils.commitment import (
    validate_commitment_policy_on_decrypt,
    validate_commitment_policy_on_encrypt,
)
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class V3DefaultCryptoMaterialsManager(CryptoMaterialsManager):
    """Copy of the default crypto material manager for ESDK V3.

    This is a copy-paste of the DefaultCryptoMaterialsManager implementation
    from the V3 ESDK commit: 98b5eb7c2bd7d1b2a3380aacfa508e8721c4d8a9
    This CMM is used to explicitly assert that the V3 implementation of
    the DefaultCMM is compatible with future version's logic,
    which implicitly asserts that custom implementations of V3-compatible CMMs
    are also compatible with future version's logic.

    :param master_key_provider: Master key provider to use
    :type master_key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """

    master_key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyProvider))

    def _generate_signing_key_and_update_encryption_context(self, algorithm, encryption_context):
        """Generates a signing key based on the provided algorithm.

        :param algorithm: Algorithm for which to generate signing key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context from request
        :returns: Signing key bytes
        :rtype: bytes or None
        """
        _LOGGER.debug("Generating signing key")
        if algorithm.signing_algorithm_info is None:
            return None

        signer = Signer(algorithm=algorithm, key=generate_ecc_signing_key(algorithm=algorithm))
        encryption_context[ENCODED_SIGNER_KEY] = to_str(signer.encoded_public_key())
        return signer.key_bytes()

    def get_encryption_materials(self, request):
        """Creates encryption materials using underlying master key provider.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises MasterKeyProviderError: if no master keys are available from the underlying master key provider
        :raises MasterKeyProviderError: if the primary master key provided by the underlying master key provider
            is not included in the full set of master keys provided by that provider
        :raises ActionNotAllowedError: if the commitment policy in the request is violated by the algorithm being
            used
        """
        default_algorithm = ALGORITHM
        if request.commitment_policy in (
            CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        ):
            default_algorithm = ALGORITHM_COMMIT_KEY
        algorithm = request.algorithm if request.algorithm is not None else default_algorithm

        validate_commitment_policy_on_encrypt(request.commitment_policy, request.algorithm)

        encryption_context = request.encryption_context.copy()

        signing_key = self._generate_signing_key_and_update_encryption_context(algorithm, encryption_context)

        primary_master_key, master_keys = self.master_key_provider.master_keys_for_encryption(
            encryption_context=encryption_context,
            plaintext_rostream=request.plaintext_rostream,
            plaintext_length=request.plaintext_length,
        )
        if not master_keys:
            raise MasterKeyProviderError("No Master Keys available from Master Key Provider")
        if primary_master_key not in master_keys:
            raise MasterKeyProviderError("Primary Master Key not in provided Master Keys")

        data_encryption_key, encrypted_data_keys = prepare_data_keys(
            primary_master_key=primary_master_key,
            master_keys=master_keys,
            algorithm=algorithm,
            encryption_context=encryption_context,
        )

        _LOGGER.debug("Post-encrypt encryption context: %s", encryption_context)

        return EncryptionMaterials(
            algorithm=algorithm,
            data_encryption_key=data_encryption_key,
            encrypted_data_keys=encrypted_data_keys,
            encryption_context=encryption_context,
            signing_key=signing_key,
        )

    def _load_verification_key_from_encryption_context(self, algorithm, encryption_context):
        """Loads the verification key from the encryption context if used by algorithm suite.

        :param algorithm: Algorithm for which to generate signing key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context from request
        :returns: Raw verification key
        :rtype: bytes
        :raises SerializationError: if algorithm suite requires message signing and no verification key is found
        """
        encoded_verification_key = encryption_context.get(ENCODED_SIGNER_KEY, None)

        if algorithm.signing_algorithm_info is not None and encoded_verification_key is None:
            raise SerializationError("No signature verification key found in header for signed algorithm.")

        if algorithm.signing_algorithm_info is None:
            if encoded_verification_key is not None:
                raise SerializationError("Signature verification key found in header for non-signed algorithm.")
            return None

        verifier = Verifier.from_encoded_point(algorithm=algorithm, encoded_point=encoded_verification_key)
        return verifier.key_bytes()

    def decrypt_materials(self, request):
        """Obtains a plaintext data key from one or more encrypted data keys
        using underlying master key provider.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        validate_commitment_policy_on_decrypt(request.commitment_policy, request.algorithm)

        data_key = self.master_key_provider.decrypt_data_key_from_list(
            encrypted_data_keys=request.encrypted_data_keys,
            algorithm=request.algorithm,
            encryption_context=request.encryption_context,
        )
        verification_key = self._load_verification_key_from_encryption_context(
            algorithm=request.algorithm, encryption_context=request.encryption_context
        )

        return DecryptionMaterials(data_key=data_key, verification_key=verification_key)


def encrypt_decrypt_with_v3_default_cmm(key_arn,
                                        source_plaintext,
                                        botocore_session):
    """Encrypts and decrypts a string using a V3 default CMM.

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Create a KMS master key provider.
    kms_kwargs = dict(key_ids=[key_arn])
    if botocore_session is not None:
        kms_kwargs["botocore_session"] = botocore_session
    master_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)

    # Create the V3 default CMM (V3DefaultCryptoMaterialsManager) using the master_key_provider
    default_cmm = V3DefaultCryptoMaterialsManager(master_key_provider=master_key_provider)

    # Encrypt the plaintext source data
    ciphertext, encryptor_header = client.encrypt(
        source=source_plaintext,
        materials_manager=default_cmm
    )

    # Decrypt the ciphertext
    cycled_plaintext, decrypted_header = client.decrypt(
        source=ciphertext,
        key_provider=master_key_provider
    )

    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source plaintext
    assert cycled_plaintext == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes all key pairs from
    # the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    #
    # In production, always use a meaningful encryption context. In this sample, we omit the
    # encryption context (no key pairs).
    assert all(
        pair in decrypted_header.encryption_context.items() for pair in encryptor_header.encryption_context.items()
    )