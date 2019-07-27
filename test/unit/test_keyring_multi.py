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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.exceptions import GenerateKeyError, EncryptKeyError
from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.keyring.base import EncryptedDataKey, Keyring
from aws_encryption_sdk.keyring.multi_keyring import MultiKeyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, RawRSAKeyring, WrappingKey
from aws_encryption_sdk.internal.formatting import serialize
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import KeyringTrace, MasterKeyInfo, RawDataKey

from pytest_mock import mocker  # noqa pylint: disable=unused-import

from .test_utils import get_encryption_materials_without_data_key, get_encryption_materials_with_data_key, \
    get_multi_keyring_with_generator_and_children, get_multi_keyring_with_no_children, \
    get_multi_keyring_with_no_generator, get_identity_keyring, get_decryption_materials_with_data_key, \
    get_decryption_materials_without_data_key

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.unit, pytest.mark.local]


_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY_AES = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_SIGNING_KEY = b"aws-crypto-public-key"

mock_generator = MagicMock()
mock_generator.__class__ = RawAESKeyring
mock_child_1 = MagicMock()
mock_child_1.__class__ = RawAESKeyring
mock_child_2 = MagicMock()
mock_child_2.__class__ = RawAESKeyring


@pytest.fixture
def patch_encrypt(mocker):
    mocker.patch.object(serialize, "serialize_raw_master_key_prefix")
    return serialize.serialize_raw_master_key_prefix


def test_parent():
    assert issubclass(MultiKeyring, Keyring)


def test_keyring_with_generator_but_no_children():
    test_multi_keyring = MultiKeyring(
        generator=RawAESKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_key=_WRAPPING_KEY_AES,
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
        )
    )
    assert isinstance(test_multi_keyring.generator,RawAESKeyring)


def test_keyring_with_children_but_no_generator():
    test_multi_keyring = MultiKeyring(
        children=[
            RawAESKeyring(
                key_namespace=_PROVIDER_ID,
                key_name=_KEY_ID,
                wrapping_key=_WRAPPING_KEY_AES,
                wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
            )
        ]
    )
    assert isinstance(test_multi_keyring.children, list)


def test_keyring_with_no_generator_no_children():
    with pytest.raises(TypeError) as exc_info:
        MultiKeyring()
    assert exc_info.match("At least one of generator or children must be provided")


def test_children_not_keyrings():
    with pytest.raises(TypeError) as exc_info:
        MultiKeyring(
            children=[
                WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
            ]
        )
    assert exc_info.errisinstance(TypeError)


def test_on_encrypt_with_no_generator_no_data_encryption_key():
    test_multi_keyring = get_multi_keyring_with_no_generator()
    with pytest.raises(EncryptKeyError) as exc_info:
        test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_key())
    assert exc_info.match("Generator keyring not provided and encryption materials do not already "
                          "contain a plaintext data key.")


def test_identity_keyring_as_generator_and_no_data_encryption_key():
    test_multi_keyring = MultiKeyring(
        generator=get_identity_keyring()
    )
    with pytest.raises(GenerateKeyError) as exc_info:
        test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_key())
    assert exc_info.match("Unable to generate data encryption key.")


def test_number_of_encrypted_data_keys_without_generator_with_children():
    test_multi_keyring = get_multi_keyring_with_no_generator()
    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_key())
    assert len(test.encrypted_data_keys) == len(test_multi_keyring.children)


def test_number_of_encrypted_data_keys_without_children_with_generator():
    test_multi_keyring = get_multi_keyring_with_no_children()
    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_key())
    assert len(test.encrypted_data_keys) == 1


def test_number_of_encrypted_data_keys_with_generator_and_children():
    test_multi_keyring = get_multi_keyring_with_generator_and_children()
    number_of_children = len(test_multi_keyring.children)
    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_key())
    assert len(test.encrypted_data_keys) == number_of_children + 1


def test_on_encrypt_when_data_encryption_key_given():
    test_multi_keyring = MultiKeyring(
        generator=mock_generator,
        children=[
            mock_child_1,
            mock_child_2
        ]
    )
    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_key())
    mock_generator.on_encrypt.assert_called_once()
    for keyring in test_multi_keyring.children:
        keyring.on_encrypt.assert_called_once()


def test_on_encrypt_edk_length_when_keyring_generates_but_does_not_encrypt(patch_encrypt):
    patch_encrypt.side_effect = Exception("Raw AES Keyring unable to encrypt data key")
    test_multi_keyring = get_multi_keyring_with_no_children()
    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_key())
    assert test.data_encryption_key is not None
    # print(test.encrypted_data_keys)
    assert len(test.encrypted_data_keys) == len(get_encryption_materials_without_data_key().encrypted_data_keys)


def test_on_decrypt_when_data_encryption_key_given():
    test_multi_keyring = MultiKeyring(
        generator=mock_generator,
        children=[
            mock_child_1,
            mock_child_2
        ]
    )
    test = test_multi_keyring.on_decrypt(decryption_materials=get_decryption_materials_with_data_key(),
                                         encrypted_data_keys=[])
    mock_generator.on_decrypt.assert_not_called()
    for keyring in test_multi_keyring.children:
        keyring.on_decrypt.assert_not_called()

#
# def test_every_keyring_called_when_edk_not_added():
#
