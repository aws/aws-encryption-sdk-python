# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Test suite for ``aws_encryption_sdk.keyrings.master_key``."""
import itertools

import pytest

from aws_encryption_sdk.exceptions import (
    InvalidCryptographicMaterialsError,
    MasterKeyProviderError,
    UnknownIdentityError,
)
from aws_encryption_sdk.identifiers import KeyringTraceFlag
from aws_encryption_sdk.internal.defaults import ALGORITHM
from aws_encryption_sdk.keyrings.master_key import MasterKeyProviderKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import MasterKeyInfo, RawDataKey

from ..unit_test_utils import (
    DisjointMasterKeyProvider,
    EmptyMasterKeyProvider,
    EphemeralRawMasterKeyProvider,
    FailingDecryptMasterKeyProvider,
    UnknownDataKeyInfoMasterKeyProvider,
    ephemeral_raw_aes_master_key,
    ephemeral_raw_rsa_master_key,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _encryption_contexts():
    yield pytest.param({}, id="no encryption context")
    yield pytest.param({"foo": "bar"}, id="some encryption context")


@pytest.mark.parametrize("encryption_context", _encryption_contexts())
def test_cycle(encryption_context):
    mkp = ephemeral_raw_rsa_master_key()
    keyring = MasterKeyProviderKeyring(master_key_provider=mkp)

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context=encryption_context)

    final_encryption_materials = keyring.on_encrypt(encryption_materials=encryption_materials)

    decryption_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context=encryption_context)

    final_decryption_materials = keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=final_encryption_materials.encrypted_data_keys
    )

    assert (
        final_encryption_materials.data_encryption_key.data_key
        == final_decryption_materials.data_encryption_key.data_key
    )


def _master_key_flags_on_encrypt():
    single_raw_rsa_mkp = ephemeral_raw_rsa_master_key()
    yield pytest.param(
        single_raw_rsa_mkp,
        single_raw_rsa_mkp.key_provider,
        [KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY, KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY],
        id="single master key : raw RSA",
    )

    single_raw_aes_mkp = ephemeral_raw_aes_master_key()
    yield pytest.param(
        single_raw_aes_mkp,
        single_raw_aes_mkp.key_provider,
        [
            KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
            KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY,
            KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX,
        ],
        id="single master key : raw AES",
    )

    raw_provider = EphemeralRawMasterKeyProvider()
    raw_provider.add_master_key(b"aes-256")
    raw_provider.add_master_key(b"rsa-4096")
    yield pytest.param(
        raw_provider,
        raw_provider.master_key(b"aes-256").key_provider,
        [
            KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
            KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY,
            KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX,
        ],
        id="multiple master keys : raw AES generate and encrypt",
    )
    yield pytest.param(
        raw_provider,
        raw_provider.master_key(b"rsa-4096").key_provider,
        [KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY],
        id="multiple master keys : raw RSA encrypt only",
    )


@pytest.mark.parametrize("master_key_provider, master_key_for_flags, expected_flags", _master_key_flags_on_encrypt())
@pytest.mark.parametrize("encryption_context", _encryption_contexts())
def test_keyring_flags_on_encrypt(master_key_provider, master_key_for_flags, expected_flags, encryption_context):
    keyring = MasterKeyProviderKeyring(master_key_provider=master_key_provider)

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context=encryption_context)

    final_encryption_materials = keyring.on_encrypt(encryption_materials=encryption_materials)

    actual_flags = list(
        itertools.chain.from_iterable(
            (
                trace.flags
                for trace in final_encryption_materials.keyring_trace
                if trace.wrapping_key == master_key_for_flags
            )
        )
    )
    assert len(actual_flags) == len(expected_flags)
    assert set(actual_flags) == set(expected_flags)


def _master_key_flags_on_decrypt():
    single_raw_rsa_mkp = ephemeral_raw_rsa_master_key()
    yield pytest.param(
        single_raw_rsa_mkp,
        single_raw_rsa_mkp,
        [KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY],
        id="single master key : raw RSA",
    )

    single_raw_aes_mkp = ephemeral_raw_aes_master_key()
    yield pytest.param(
        single_raw_aes_mkp,
        single_raw_aes_mkp,
        [KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY, KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX,],
        id="single master key : raw AES",
    )

    raw_provider = EphemeralRawMasterKeyProvider()
    raw_provider.add_master_key(b"aes-256")
    raw_provider.add_master_key(b"rsa-4096")
    yield pytest.param(
        raw_provider,
        raw_provider.master_key(b"aes-256"),
        [KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY, KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX,],
        id="multiple master key encrypt : raw AES decrypt",
    )
    yield pytest.param(
        raw_provider,
        raw_provider.master_key(b"rsa-4096"),
        [KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY],
        id="multiple master key encrypt : raw RSA decrypt",
    )


@pytest.mark.parametrize(
    "master_key_provider_for_encrypt, master_key_for_decrypt, expected_flags", _master_key_flags_on_decrypt()
)
@pytest.mark.parametrize("encryption_context", _encryption_contexts())
def test_keyring_flags_on_decrypt(
    master_key_provider_for_encrypt, master_key_for_decrypt, expected_flags, encryption_context
):
    keyring = MasterKeyProviderKeyring(master_key_provider=master_key_provider_for_encrypt)

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context=encryption_context)

    final_encryption_materials = keyring.on_encrypt(encryption_materials=encryption_materials)

    decrypt_keyring = MasterKeyProviderKeyring(master_key_provider=master_key_for_decrypt)

    decryption_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context=encryption_context)

    final_decryption_materials = decrypt_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=final_encryption_materials.encrypted_data_keys
    )

    actual_flags = list(
        itertools.chain.from_iterable(
            (
                trace.flags
                for trace in final_decryption_materials.keyring_trace
                if trace.wrapping_key == master_key_for_decrypt.key_provider
            )
        )
    )
    assert len(actual_flags) == len(expected_flags)
    assert set(actual_flags) == set(expected_flags)


def test_on_encrypt_no_master_keys():
    keyring = MasterKeyProviderKeyring(master_key_provider=EmptyMasterKeyProvider())

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    with pytest.raises(MasterKeyProviderError) as excinfo:
        keyring.on_encrypt(encryption_materials=encryption_materials)

    excinfo.match("No Master Keys available from Master Key Provider")


def test_on_encrypt_primary_master_key_not_in_master_keys():
    keyring = MasterKeyProviderKeyring(master_key_provider=DisjointMasterKeyProvider())

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    with pytest.raises(MasterKeyProviderError) as excinfo:
        keyring.on_encrypt(encryption_materials=encryption_materials)

    excinfo.match("Primary Master Key not in provided Master Keys")


@pytest.mark.parametrize("encryption_context", _encryption_contexts())
def test_on_encrypt_with_existing_data_key(encryption_context):
    keyring = MasterKeyProviderKeyring(master_key_provider=ephemeral_raw_aes_master_key())

    encryption_materials = EncryptionMaterials(
        algorithm=ALGORITHM,
        encryption_context=encryption_context,
        data_encryption_key=RawDataKey(key_provider=MasterKeyInfo(provider_id="foo", key_info=b"bar"), data_key=b""),
    )

    with pytest.raises(InvalidCryptographicMaterialsError):
        keyring.on_encrypt(encryption_materials=encryption_materials)


def test_on_decrypt_with_existing_data_key():
    keyring = MasterKeyProviderKeyring(master_key_provider=ephemeral_raw_aes_master_key())

    decryption_materials = DecryptionMaterials(
        algorithm=ALGORITHM,
        encryption_context={},
        data_encryption_key=RawDataKey(key_provider=MasterKeyInfo(provider_id="foo", key_info=b"bar"), data_key=b""),
    )

    final_decryption_materials = keyring.on_decrypt(decryption_materials=decryption_materials, encrypted_data_keys=[])

    assert not final_decryption_materials.keyring_trace


def test_on_decrypt_master_key_throws_error():
    mkp = FailingDecryptMasterKeyProvider()
    mkp.add_master_key(b"aes-256")
    mkp.add_master_key(b"rsa-4096")
    keyring = MasterKeyProviderKeyring(master_key_provider=mkp)

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    final_encryption_materials = keyring.on_encrypt(encryption_materials=encryption_materials)

    decryption_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    final_decryption_materials = keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=final_encryption_materials.encrypted_data_keys,
    )
    assert final_decryption_materials.data_encryption_key is None


def test_on_decrypt_master_key_not_in_keyring_trace():
    mkp = UnknownDataKeyInfoMasterKeyProvider()
    mkp.add_master_key(b"aes-256")
    mkp.add_master_key(b"rsa-4096")
    keyring = MasterKeyProviderKeyring(master_key_provider=mkp)

    encryption_materials = EncryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    final_encryption_materials = keyring.on_encrypt(encryption_materials=encryption_materials)

    decryption_materials = DecryptionMaterials(algorithm=ALGORITHM, encryption_context={})

    with pytest.raises(UnknownIdentityError) as excinfo:
        keyring.on_decrypt(
            decryption_materials=decryption_materials,
            encrypted_data_keys=final_encryption_materials.encrypted_data_keys,
        )

    excinfo.match(r"Unable to locate master key for *")
