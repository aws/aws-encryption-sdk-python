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
"""Unit tests for Multi keyring."""

import pytest
import six
from mock import MagicMock, patch, sentinel

from aws_encryption_sdk.exceptions import GenerateKeyError, EncryptKeyError
from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.keyring.base import EncryptedDataKey, Keyring
from aws_encryption_sdk.keyring.multi_keyring import MultiKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import KeyringTrace, MasterKeyInfo, RawDataKey

from .test_utils import _MULTI_KEYRING_WITH_NO_GENERATOR, _ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY, \
    _MULTI_KEYRING, _ENCRYPTION_MATERIALS_WITH_DATA_KEY

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_SIGNING_KEY = b"aws-crypto-public-key"


class TestMultiKeyring(object):

    def test_parent(self):
        assert issubclass(MultiKeyring, Keyring)

    def test_keyring_with_no_generator_no_children(self):
        with pytest.raises(TypeError) as exc_info:
            MultiKeyring()
        assert exc_info.match("At least one of generator or children must be provided")

    def test_children_not_keyrings(self):
        with pytest.raises(TypeError):
            MultiKeyring(
                children=[
                    WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
                ]
            )

    def test_no_generator_no_data_encryption_key(self):
        test_multi_keyring = _MULTI_KEYRING_WITH_NO_GENERATOR
        with pytest.raises(EncryptKeyError) as exc_info:
            test_multi_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)
        assert exc_info.match("Generator keyring not provided and encryption materials do not already "
                              "contain a plaintext data key.")

    @patch("aws_encryption_sdk.keyring.raw_keyring.generate_data_key")
    def test_data_key_not_generated(self, mock_generate):
        mock_generate.return_value = None
        test_multi_keyring = _MULTI_KEYRING
        with pytest.raises(GenerateKeyError) as exc_info:
            test_multi_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITHOUT_DATA_KEY)
        assert exc_info.match("Unable to generate data encryption key")

    def test_number_of_encrypted_data_keys_without_generator(self):
        test_multi_keyring = _MULTI_KEYRING_WITH_NO_GENERATOR
        test = test_multi_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITH_DATA_KEY)
        assert len(test.encrypted_data_keys) == len(test_multi_keyring.children)

    def test_number_of_encrypted_data_keys_with_generator(self):
        test_multi_keyring = _MULTI_KEYRING
        test = test_multi_keyring.on_encrypt(encryption_materials=_ENCRYPTION_MATERIALS_WITH_DATA_KEY)
        assert len(test.encrypted_data_keys) == len(test_multi_keyring.children) + 1
