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
from attr.validators import instance_of, optional

from ..exceptions import InvalidCryptographicMaterialsError, SerializationError
from ..internal.crypto.authentication import Signer, Verifier
from ..internal.crypto.elliptic_curve import generate_ecc_signing_key
from ..internal.defaults import ALGORITHM, ENCODED_SIGNER_KEY
from ..internal.str_ops import to_str
from ..key_providers.base import MasterKeyProvider
from ..keyrings.base import Keyring
from ..keyrings.master_key import MasterKeyProviderKeyring
from . import DecryptionMaterials, DecryptionMaterialsRequest, EncryptionMaterials, EncryptionMaterialsRequest
from .base import CryptoMaterialsManager

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class DefaultCryptoMaterialsManager(CryptoMaterialsManager):
    """Default crypto material manager.

    .. versionadded:: 1.3.0

    .. versionadded:: 1.5.0
       The *keyring* parameter.

    :param MasterKeyProvider master_key_provider: Master key provider to use
        (either `keyring` or `master_key_provider` is required)
    :param Keyring keyring: Keyring to use
        (either `keyring` or `master_key_provider` is required)
    """

    algorithm = ALGORITHM
    master_key_provider = attr.ib(default=None, validator=optional(instance_of(MasterKeyProvider)))
    keyring = attr.ib(default=None, validator=optional(instance_of(Keyring)))

    def __attrs_post_init__(self):
        """Make sure that exactly one key provider is set and prep the keyring if needed."""
        both = self.keyring is not None and self.master_key_provider is not None
        neither = self.keyring is None and self.master_key_provider is None

        if both or neither:
            raise TypeError("Exactly one of 'master_key_provider' or 'keyring' must be provided.")

        if self.keyring is None:
            self.keyring = MasterKeyProviderKeyring(master_key_provider=self.master_key_provider)

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
        # type: (EncryptionMaterialsRequest) -> EncryptionMaterials
        """Creates encryption materials using underlying master key provider.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :raises MasterKeyProviderError: if no master keys are available from the underlying master key provider
        :raises MasterKeyProviderError: if the primary master key provided by the underlying master key provider
            is not included in the full set of master keys provided by that provider
        """
        algorithm = request.algorithm if request.algorithm is not None else self.algorithm
        encryption_context = request.encryption_context.copy()

        signing_key = self._generate_signing_key_and_update_encryption_context(algorithm, encryption_context)

        expected_encryption_context = encryption_context.copy()

        encryption_materials = EncryptionMaterials(
            algorithm=algorithm, encryption_context=encryption_context, signing_key=signing_key,
        )

        final_materials = self.keyring.on_encrypt(encryption_materials=encryption_materials)

        if not final_materials.is_complete:
            raise InvalidCryptographicMaterialsError("Encryption materials are incomplete!")

        materials_are_valid = (
            final_materials.algorithm is algorithm,
            final_materials.encryption_context == expected_encryption_context,
            final_materials.signing_key is signing_key,
        )
        if not all(materials_are_valid):
            raise InvalidCryptographicMaterialsError("Encryption materials do not match request!")

        _LOGGER.debug("Post-encrypt encryption context: %s", final_materials.encryption_context)

        return final_materials

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
        # type: (DecryptionMaterialsRequest) -> DecryptionMaterials
        """Obtains a plaintext data key from one or more encrypted data keys
        using underlying master key provider.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        verification_key = self._load_verification_key_from_encryption_context(
            algorithm=request.algorithm, encryption_context=request.encryption_context
        )
        decryption_materials = DecryptionMaterials(
            algorithm=request.algorithm,
            encryption_context=request.encryption_context,
            verification_key=verification_key,
        )

        final_materials = self.keyring.on_decrypt(
            decryption_materials=decryption_materials, encrypted_data_keys=request.encrypted_data_keys
        )

        if not final_materials.is_complete:
            raise InvalidCryptographicMaterialsError("Materials are incomplete!")

        materials_are_valid = (
            final_materials.algorithm is request.algorithm,
            final_materials.encryption_context == request.encryption_context,
            final_materials.verification_key is verification_key,
        )
        if not all(materials_are_valid):
            raise InvalidCryptographicMaterialsError("Decryption materials do not match request!")

        return final_materials
