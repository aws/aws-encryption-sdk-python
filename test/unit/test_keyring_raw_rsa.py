# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit tests for Raw AES keyring."""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from mock import MagicMock, patch, sentinel

from aws_encryption_sdk.exceptions import GenerateKeyError
from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.keyring.base import EncryptedDataKey, Keyring
from aws_encryption_sdk.keyring.raw_keyring import RawRSAKeyring, generate_data_key
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import KeyringTrace, MasterKeyInfo, RawDataKey

from .test_values import VALUES
# from .test_utils import NullRawAESKeyring

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
_SIGNING_KEY = b"aws-crypto-public-key"
_DATA_KEY = (
    b"\x00\xfa\x8c\xdd\x08Au\xc6\x92_4\xc5\xfb\x90\xaf\x8f\xa1D\xaf\xcc\xd25" b"\xa8\x0b\x0b\x16\x92\x91W\x01\xb7\x84"
)
_ENCRYPTION_MATERIALS_WITH_DATA_KEY = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    data_encryption_key=RawDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
    ),
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
    keyring_trace=[
        KeyringTrace(
            wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
        )
    ],
)

_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
)

_ENCRYPTION_MATERIALS_WITH_ENCRYPTED_DATA_KEY = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    data_encryption_key=RawDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
    ),
    encrypted_data_keys=[
        EncryptedDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
            b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
        )
    ],
    encryption_context=_ENCRYPTION_CONTEXT,
    signing_key=_SIGNING_KEY,
    keyring_trace=[
        KeyringTrace(
            wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY},
        )
    ],
)

_DECRYPTION_MATERIALS_WITH_DATA_KEY = DecryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    data_encryption_key=RawDataKey(
        key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
    ),
    encryption_context=_ENCRYPTION_CONTEXT,
    verification_key=b"ex_verification_key",
    keyring_trace=[KeyringTrace(
        wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
        flags={KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY}
    )]
)

_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY = DecryptionMaterials(
    verification_key=b"ex_verification_key",
)


class TestRawRSAKeyring(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        self.mock_encrypted_data_key = EncryptedDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            encrypted_data_key=VALUES["encrypted_data_key"],
        )
        self.mock_encryption_materials = MagicMock()
        self.mock_encryption_materials.__class__ = EncryptionMaterials

    def test_parent(self):
        assert issubclass(RawRSAKeyring, Keyring)

    # def test_initialization(self):
    #     test = RawAESKeyring(
    #         key_namespace=_PROVIDER_ID,
    #         key_name=_KEY_ID,
    #         wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    #         wrapping_key=_WRAPPING_KEY,
    #     )
    #     assert test.__getattribute__(key_provider) == self.mock_encrypted_data_key.key_provider

    @patch("aws_encryption_sdk.keyring.raw_keyring.generate_data_key")
    def test_data_encryption_key_provided(self, mock_generate_data_key):
        mock_generate_data_key.return_value = _DATA_KEY
        test_raw_rsa_keyring = RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=_WRAPPING_KEY,
        )

        test = test_raw_rsa_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITH_DATA_KEY)
        # Check if keyring is generated
        assert not mock_generate_data_key.called

        # Check if data encryption key is encrypted
        assert test.encrypted_data_keys is not None

    def test_data_encryption_key_generated(self):
        test_raw_rsa_keyring = RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=_WRAPPING_KEY,
        )
        test = test_raw_rsa_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)

        # Check if key is generated
        if not test.data_encryption_key:
            # Check if error thrown if data key is not generated
            assert pytest.raises(GenerateKeyError, "Unable to generate data encryption key.")
        else:
            # Check if data key is generated
            assert test.data_encryption_key and test.data_encryption_key is not None
        assert test.encrypted_data_keys and test.encrypted_data_keys is not None

    @patch("aws_encryption_sdk.keyring.raw_keyring.generate_data_key")
    def test_encrypted_data_key_provided(self, mock_generate_data_key):
        mock_generate_data_key.return_value = _DATA_KEY
        test_raw_rsa_keyring = RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=_WRAPPING_KEY,
        )
        test = test_raw_rsa_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITH_ENCRYPTED_DATA_KEY)

        # Check if generate_data_key is called
        assert not mock_generate_data_key.called
        #
        # Check if encrypt is called
        assert len(test.encrypted_data_keys) == len(_ENCRYPTION_MATERIALS_WITH_ENCRYPTED_DATA_KEY.encrypted_data_keys)

    # @patch("aws_encryption_sdk.key_providers.raw.os.urandom")
    # def test_data_key_not_generated(self, mock_os_urandom):
    #     mock_os_urandom.return_value = None
    #     test_raw_aes_keyring = RawAESKeyring(
    #         key_namespace=_PROVIDER_ID,
    #         key_name=_KEY_ID,
    #         wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    #         wrapping_key=_WRAPPING_KEY,
    #     )
    #     test = test_raw_aes_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)
    #     assert pytest.raises(GenerateKeyError, "Unable to generate data encryption key.")

    @patch("aws_encryption_sdk.keyring.raw_keyring.generate_data_key")
    def test_data_key_not_generated(self, mock_generate_data_key):
        mock_generate_data_key.return_value = None
        test_raw_rsa_keyring = RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=_WRAPPING_KEY,
        )
        test = test_raw_rsa_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)
        assert pytest.raises(GenerateKeyError)

    @patch("aws_encryption_sdk.internal.crypto.wrapping_keys.WrappingKey.decrypt")
    def test_decrypt_when_data_key_provided(self, mock_decrypt):
        mock_decrypt.return_value = _DATA_KEY
        test_raw_rsa_keyring = RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=_WRAPPING_KEY,
        )
        test = test_raw_rsa_keyring.on_decrypt(decryption_materials=_DECRYPTION_MATERIALS_WITH_DATA_KEY,
                                               encrypted_data_keys=[self.mock_encrypted_data_key])
        assert not mock_decrypt.called

    # @patch("aws_encryption_sdk.internal.crypto.wrapping_keys.WrappingKey.decrypt")
    # def test_decrypt_when_data_key_not_provided(self, mock_decrypt):
    #     mock_decrypt.return_value = _DATA_KEY
    #     test_raw_aes_keyring = RawAESKeyring(
    #         key_namespace=_PROVIDER_ID,
    #         key_name=_KEY_ID,
    #         wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    #         wrapping_key=_WRAPPING_KEY,
    #     )
    #
    #     test = test_raw_aes_keyring.on_decrypt(decryption_materials=_DECRYPTION_MATERIALS_WITHOUT_DATA_KEY,
    #                                            encrypted_data_keys=[
    #                                                EncryptedDataKey(
    #                                                 key_provider=MasterKeyInfo(
    #                                                     provider_id=_PROVIDER_ID,
    #                                                     key_info=_KEY_ID),
    #                                                 encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\
    #                                                 xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
    #                                                 b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\
    #                                                 x07FzE\xde",
    #                                                 )
    #                                             ]
    #                                            )
    #     assert mock_decrypt.called
