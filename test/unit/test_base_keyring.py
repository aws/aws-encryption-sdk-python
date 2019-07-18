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
import six

from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.keyring.base import EncryptedDataKey, Keyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import MasterKeyInfo

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

_encrypted_data_keys = [
    EncryptedDataKey(
        key_provider=MasterKeyInfo(provider_id="Random Raw Keys", key_info=b"5325b043-5843-4629-869c-64794af77ada"),
        encrypted_data_key=six.b(
            "\n \x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW"
            "\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x12\xa7\x01\x01\x01\x01\x00x"
            "\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW"
            "\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00~0|\x06\t*\x86H"
            "\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01\x000h\x06\t*\x86H\x86\xf7\r"
            "\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xc9rP"
            "\xa1\x08t6{\xf2\xfd\xf1\xb3\x02\x01\x10\x80;D\xa4\xed`qP~c\x0f\xa0d"
            "\xd5\xa2Kj\xc7\xb2\xc6\x1e\xec\xfb\x0fK\xb2*\xd5\t2\x81pR\xee\xd1"
            '\x1a\xde<"\x1b\x98\x88\x8b\xf4&\xdaB\x95I\xd2\xff\x10\x13\xfc\x1aX'
            "\x08,/\x8b\x8b"
        ),
    )
]


def test_keyring_no_encrypt():
    class KeyringNoEncrypt(Keyring):
        def on_decrypt(self, _decryption_materials, _encrypted_data_keys):
            # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
            return _decryption_materials

    with pytest.raises(TypeError) as exc_info:
        KeyringNoEncrypt()
    exc_info.match("Can't instantiate abstract class KeyringNoEncrypt with abstract methods on_encrypt")


def test_keyring_no_decrypt():
    class KeyringNoDecrypt(Keyring):
        def on_encrypt(self, _encryption_materials):
            # type: (EncryptionMaterials) -> EncryptionMaterials
            return _encryption_materials

    with pytest.raises(TypeError) as exc_info:
        KeyringNoDecrypt()
    exc_info.match("Can't instantiate abstract class KeyringNoDecrypt with abstract methods on_decrypt")
