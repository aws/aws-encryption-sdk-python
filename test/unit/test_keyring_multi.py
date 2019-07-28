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
from mock import MagicMock
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk.exceptions import EncryptKeyError, GenerateKeyError
from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.internal.formatting import serialize
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.keyring.multi_keyring import MultiKeyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring

from .test_utils import (
    IdentityKeyring,
    OnlyGenerateKeyring,
    get_decryption_materials_with_data_key,
    get_decryption_materials_without_data_key,
    get_encryption_materials_with_data_key,
    get_encryption_materials_with_encrypted_data_key,
    get_encryption_materials_without_data_key,
    get_multi_keyring_with_generator_and_children,
    get_multi_keyring_with_no_children,
    get_multi_keyring_with_no_generator,
)

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

mock_child_3 = MagicMock()
mock_child_3.__class__ = RawAESKeyring
mock_child_3.on_decrypt.return_value = get_decryption_materials_with_data_key()


mock_generator_does_not_add_edk = MagicMock()
mock_generator_does_not_add_edk.__class__ = OnlyGenerateKeyring

mock_child_1_does_not_add_edk = MagicMock()
mock_child_1_does_not_add_edk.__class__ = OnlyGenerateKeyring

mock_child_2_does_not_add_edk = MagicMock()
mock_child_2_does_not_add_edk.__class__ = OnlyGenerateKeyring


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
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        )
    )
    assert isinstance(test_multi_keyring.generator, RawAESKeyring)


def test_keyring_with_children_but_no_generator():
    test_multi_keyring = MultiKeyring(
        children=[
            RawAESKeyring(
                key_namespace=_PROVIDER_ID,
                key_name=_KEY_ID,
                wrapping_key=_WRAPPING_KEY_AES,
                wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
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
        MultiKeyring(children=[WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING])
    assert exc_info.errisinstance(TypeError)


def test_on_encrypt_with_no_generator_no_data_encryption_key():
    test_multi_keyring = get_multi_keyring_with_no_generator()
    with pytest.raises(EncryptKeyError) as exc_info:
        test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_key())
    assert exc_info.match(
        "Generator keyring not provided and encryption materials do not already " "contain a plaintext data key."
    )


def test_identity_keyring_as_generator_and_no_data_encryption_key():
    test_multi_keyring = MultiKeyring(generator=IdentityKeyring())
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
    test_multi_keyring = MultiKeyring(generator=mock_generator, children=[mock_child_1, mock_child_2])
    test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_data_key())
    for keyring in test_multi_keyring._decryption_keyrings:
        keyring.on_encrypt.assert_called_once()


def test_on_encrypt_edk_length_when_keyring_generates_but_does_not_encrypt():
    test_multi_keyring = MultiKeyring(generator=OnlyGenerateKeyring())
    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_without_data_key())
    assert test.data_encryption_key is not None
    assert len(test.encrypted_data_keys) == len(get_encryption_materials_without_data_key().encrypted_data_keys)

    test = test_multi_keyring.on_encrypt(encryption_materials=get_encryption_materials_with_encrypted_data_key())
    assert len(test.encrypted_data_keys) == len(get_encryption_materials_with_encrypted_data_key().encrypted_data_keys)


def test_on_decrypt_when_data_encryption_key_given():
    test_multi_keyring = MultiKeyring(generator=mock_generator, children=[mock_child_1, mock_child_2])
    test_multi_keyring.on_decrypt(decryption_materials=get_decryption_materials_with_data_key(), encrypted_data_keys=[])
    for keyring in test_multi_keyring._decryption_keyrings:
        keyring.on_decrypt.assert_not_called()


def test_on_decrypt_every_keyring_called_when_data_encryption_key_not_added():
    mock_generator.on_decrypt.return_value = get_decryption_materials_without_data_key()
    mock_child_1.on_decrypt.return_value = get_decryption_materials_without_data_key()
    mock_child_2.on_decrypt.return_value = get_decryption_materials_without_data_key()

    test_multi_keyring = MultiKeyring(generator=mock_generator, children=[mock_child_1, mock_child_2])
    test_multi_keyring.on_decrypt(
        decryption_materials=get_decryption_materials_without_data_key(), encrypted_data_keys=[]
    )

    for keyring in test_multi_keyring._decryption_keyrings:
        keyring.on_decrypt.assert_called()


# def test_no_keyring_called_after_data_encryption_key_added_when_data_encryption_key_not_given():
#     mock_generator.on_decrypt(decryption_materials=get_decryption_materials_without_data_key(),
#                               encrypted_data_keys=[])
#     mock_generator.on_decrypt.return_value = get_decryption_materials_without_data_key()
#
#     mock_child_3.on_decrypt(decryption_materials=mock_generator.on_decrypt.return_value,
#                             encrypted_data_keys=[])
#     mock_child_3.on_decrypt.return_value = get_decryption_materials_with_data_key()
#
#     mock_child_1.on_decrypt(decryption_materials=mock_child_3.on_decrypt.return_value,
#                             encrypted_data_keys=[])
#     mock_child_1.on_decrypt.return_value = get_decryption_materials_with_data_key()
#
#     mock_child_2.on_decrypt(decryption_materials=mock_child_1.on_decrypt.return_value,
#                             encrypted_data_keys=[])
#     mock_child_2.on_decrypt.return_value = get_decryption_materials_with_data_key()
#
#     test_multi_keyring = MultiKeyring(
#         generator=mock_generator,
#         children=[
#             mock_child_3,
#             mock_child_1,
#             mock_child_2,
#         ]
#     )
#     test_multi_keyring.on_decrypt(decryption_materials=get_decryption_materials_without_data_key(),
#                                   encrypted_data_keys=[])
#     mock_generator.on_decrypt.assert_called()
#     mock_child_3.on_decrypt.assert_called()
#     mock_child_1.on_decrypt.assert_not_called()
#     mock_child_2.on_decrypt.assert_not_called()

# def test_no_keyring_called_after_data_encryption_key_added_when_data_encryption_key_not_given():
#     test_multi_keyring = get_multi_keyring_with_generator_and_children()
#     test_multi_keyring.on_decrypt(decryption_materials=get_decryption_materials_without_data_key(),
#                                   encrypted_data_keys=[
#                                       EncryptedDataKey(
#                                           key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
#                                           encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9"
#                                                              b"\x7f.}\x87\x16,\x11n#\xc8p\xdb\xbf\x94\x86*Q\x06\xd2"
#                                                              b"\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
#                                       )
#                                   ])
#     for
