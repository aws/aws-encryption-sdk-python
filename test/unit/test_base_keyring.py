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
"""Unit tests for base keyring."""

import pytest

from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.keyring.base import Keyring, EncryptedDataKey
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.unit, pytest.mark.local]

_encryption_materials = EncryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    encryption_context={"encryption": "context", "values": "here"},
    signing_key=b"aws-crypto-public-key",
)

_decryption_materials = DecryptionMaterials(
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, verification_key=b"ex_verification_key"
)


def test_keyring_no_encrypt():
    class KeyringNoEncrypt(Keyring):
        def on_decrypt(self, _decryption_materials, encrypted_data_keys):
            # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
            decryption_materials = RawAESKeyring.on_decrypt(decryption_materials=_decryption_materials)
            return decryption_materials

    with pytest.raises(TypeError) as exc_info:
        KeyringNoEncrypt()
    exc_info.match("Can't instantiate abstract class KeyringNoEncrypt with abstract methods on_encrypt")


def test_keyring_no_decrypt():
    class KeyringNoDecrypt(Keyring):
        def on_encrypt(self, _encryption_materials):
            # type: (EncryptionMaterials) -> EncryptionMaterials
            encryption_materials = RawAESKeyring.on_encrypt(encryption_materials=_encryption_materials)
            return encryption_materials

    with pytest.raises(TypeError) as exc_info:
        KeyringNoDecrypt()
    exc_info.match("Can't instantiate abstract class KeyringNoDecrypt with abstract methods on_decrypt")
