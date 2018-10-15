# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Default crypto material manager class."""
import logging

import attr

from aws_encryption_sdk.exceptions import SerializationError
from aws_encryption_sdk.internal.crypto.authentication import Signer, Verifier
from aws_encryption_sdk.internal.crypto.elliptic_curve import generate_ecc_signing_key
from aws_encryption_sdk.internal.defaults import ALGORITHM, ENCODED_SIGNER_KEY
from aws_encryption_sdk.internal.str_ops import to_str
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.keyrings import Keyring
from aws_encryption_sdk.keyrings.master_key import MasterKeyKeyring

from . import DecryptionMaterials, DecryptionMaterialsRequest, EncryptionMaterials, EncryptionMaterialsRequest
from .base import CryptoMaterialsManager

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class DefaultCryptoMaterialsManager(CryptoMaterialsManager):
    """Default crypto material manager.

    .. versionadded:: 1.3.0

    :param master_key_provider: Master key provider to use
    :type master_key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """

    algorithm = ALGORITHM
    master_key_provider = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(MasterKeyProvider)), default=None
    )
    keyring = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(Keyring)), default=None)

    def __attrs_post_init__(self):
        """"""
        both_mkp_and_keyring = self.master_key_provider is not None and self.keyring is not None
        neither_mkp_nor_keyring = self.master_key_provider is None and self.keyring is None

        if both_mkp_and_keyring or neither_mkp_nor_keyring:
            raise TypeError("Exactly one of keyring or master_key_provider must be provided")

        if self.keyring is None:
            self.keyring = MasterKeyKeyring(master_key_provider=self.master_key_provider)

    @staticmethod
    def _generate_signing_key_and_update_encryption_context(algorithm, encryption_context):
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
        # type: (EncryptionMaterialsRequest) -> EncryptionMaterials
        """Creates encryption materials using underlying master key provider.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_ecryption_sdk.materials_managers.EncryptionMaterials
        :raises MasterKeyProviderError: if no master keys are available from the underlying master key provider
        :raises MasterKeyProviderError: if the primary master key provided by the underlying master key provider
            is not included in the full set of master keys provided by that provider
        """
        algorithm = request.algorithm if request.algorithm is not None else self.algorithm
        encryption_context = request.encryption_context.copy()

        signing_key = self._generate_signing_key_and_update_encryption_context(algorithm, encryption_context)

        data_key_materials = request.to_data_key_materials(algorithm, encryption_context)
        updated_data_key_materials = self.keyring.with_plaintext(
            plaintext_rostream=request.plaintext_rostream, plaintext_length=request.plaintext_length
        ).on_encrypt(data_key_materials)

        _LOGGER.debug("Post-encrypt encryption context: %s", updated_data_key_materials.encryption_context)

        return EncryptionMaterials.from_data_key_materials(
            data_key_materials=updated_data_key_materials, signing_key=signing_key
        )

    @staticmethod
    def _load_verification_key_from_encryption_context(algorithm, encryption_context):
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
        # type: (DecryptionMaterialsRequest) -> DecryptionMaterials
        """Obtains a plaintext data key from one or more encrypted data keys
        using underlying master key provider.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        encrypted_data_key_materials = request.to_data_key_materials()
        decrypted_data_key_materials = self.keyring.on_decrypt(encrypted_data_key_materials)

        verification_key = self._load_verification_key_from_encryption_context(
            algorithm=request.algorithm, encryption_context=request.encryption_context
        )

        return DecryptionMaterials(
            data_key=decrypted_data_key_materials.plaintext_data_key, verification_key=verification_key
        )
