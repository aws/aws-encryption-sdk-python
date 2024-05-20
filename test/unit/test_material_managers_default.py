# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for aws_encryption_sdk.materials_managers.default"""

import pytest
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.materials_managers.default
from aws_encryption_sdk.exceptions import ActionNotAllowedError, MasterKeyProviderError, SerializationError
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy
from aws_encryption_sdk.internal import defaults
from aws_encryption_sdk.internal.defaults import ENCODED_SIGNER_KEY
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers import EncryptionMaterials
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.structures import DataKey

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_for_dcmm_encrypt(mocker):
    mocker.patch.object(DefaultCryptoMaterialsManager, "_generate_signing_key_and_update_encryption_context")
    mock_signing_key = b"ex_signing_key"
    DefaultCryptoMaterialsManager._generate_signing_key_and_update_encryption_context.return_value = mock_signing_key
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "prepare_data_keys")
    mock_data_encryption_key = MagicMock(__class__=DataKey)
    mock_encrypted_data_keys = set([mock_data_encryption_key])
    result_pair = mock_data_encryption_key, mock_encrypted_data_keys
    aws_encryption_sdk.materials_managers.default.prepare_data_keys.return_value = result_pair
    yield result_pair, mock_signing_key


@pytest.fixture
def patch_for_dcmm_decrypt(mocker):
    mocker.patch.object(DefaultCryptoMaterialsManager, "_load_verification_key_from_encryption_context")
    mock_verification_key = b"ex_verification_key"
    DefaultCryptoMaterialsManager._load_verification_key_from_encryption_context.return_value = mock_verification_key
    yield mock_verification_key


def build_mkp():
    mock_mkp = MagicMock(__class__=MasterKeyProvider)
    mock_mkp.decrypt_data_key_from_list.return_value = MagicMock(__class__=DataKey)
    mock_mkp.master_keys_for_encryption.return_value = (
        sentinel.primary_mk,
        set([sentinel.primary_mk, sentinel.mk_a, sentinel.mk_b]),
    )
    return mock_mkp


def build_cmm():
    mock_mkp = build_mkp()
    return DefaultCryptoMaterialsManager(master_key_provider=mock_mkp)


def test_attributes_fail():
    with pytest.raises(TypeError):
        DefaultCryptoMaterialsManager(master_key_provider=None)


def test_generate_signing_key_and_update_encryption_context_no_signer():
    cmm = build_cmm()

    test = cmm._generate_signing_key_and_update_encryption_context(
        algorithm=MagicMock(signing_algorithm_info=None), encryption_context={}
    )

    assert test is None


def test_generate_signing_key_and_update_encryption_context(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "Signer")
    mock_signer = MagicMock()
    aws_encryption_sdk.materials_managers.default.Signer.return_value = mock_signer
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "generate_ecc_signing_key")
    cmm = build_cmm()
    mock_algorithm = MagicMock(signing_algorithm_info=sentinel.eccurve)
    encryption_context = {"a": "b", "c": "d"}
    check_encryption_context = encryption_context.copy()
    check_encryption_context[ENCODED_SIGNER_KEY] = mock_signer.encoded_public_key.return_value

    test = cmm._generate_signing_key_and_update_encryption_context(
        algorithm=mock_algorithm, encryption_context=encryption_context
    )

    aws_encryption_sdk.materials_managers.default.generate_ecc_signing_key.assert_called_once_with(
        algorithm=mock_algorithm
    )
    aws_encryption_sdk.materials_managers.default.Signer.assert_called_once_with(
        algorithm=mock_algorithm,
        key=aws_encryption_sdk.materials_managers.default.generate_ecc_signing_key.return_value,
    )
    assert encryption_context[ENCODED_SIGNER_KEY] is mock_signer.encoded_public_key.return_value
    assert test is mock_signer.key_bytes.return_value
    # NOTE: This encryption context check is only fully assertable because we mock out the MKP
    assert check_encryption_context == encryption_context


def test_get_encryption_materials(patch_for_dcmm_encrypt):
    encryption_context = {"a": "b"}
    mock_request = MagicMock(
        algorithm=None,
        encryption_context=encryption_context,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    expected_alg = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384  # based on commitment_policy
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)

    cmm.master_key_provider.master_keys_for_encryption.assert_called_once_with(
        encryption_context=encryption_context,
        plaintext_rostream=mock_request.plaintext_rostream,
        plaintext_length=mock_request.plaintext_length,
    )
    cmm._generate_signing_key_and_update_encryption_context.assert_called_once_with(expected_alg, encryption_context)
    aws_encryption_sdk.materials_managers.default.prepare_data_keys.assert_called_once_with(
        primary_master_key=cmm.master_key_provider.master_keys_for_encryption.return_value[0],
        master_keys=cmm.master_key_provider.master_keys_for_encryption.return_value[1],
        algorithm=expected_alg,
        encryption_context=encryption_context,
    )
    assert isinstance(test, EncryptionMaterials)
    assert test.algorithm is expected_alg
    assert test.data_encryption_key is patch_for_dcmm_encrypt[0][0]
    assert test.encrypted_data_keys is patch_for_dcmm_encrypt[0][1]
    assert test.encryption_context == encryption_context
    assert test.signing_key == patch_for_dcmm_encrypt[1]


def test_get_encryption_materials_override_algorithm(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=MagicMock(__class__=Algorithm), encryption_context={})
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)

    assert test.algorithm is mock_request.algorithm


def test_get_encryption_materials_chooses_default_noncommitting(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy FORBID_ENCRYPT_ALLOW_DECRYPT and no provided
    algorithm defaults to a non-committing algorithm."""
    mock_request = MagicMock(
        algorithm=None, encryption_context={}, commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)
    assert test.algorithm == defaults.ALGORITHM


def test_get_encryption_materials_default_alg_require_encrypt_require_decrypt(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy REQUIRE_ENCRYPT_REQUIRE_DECRYPT and no provided
    algorithm defaults to a committing algorithm."""
    mock_request = MagicMock(
        algorithm=None, encryption_context={}, commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)
    assert test.algorithm == defaults.ALGORITHM_COMMIT_KEY


def test_get_encryption_materials_default_alg_require_encrypt_allow_decrypt(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy REQUIRE_ENCRYPT_ALLOW_DECRYPT and no provided
    algorithm defaults to a committing algorithm."""
    mock_request = MagicMock(
        algorithm=None, encryption_context={}, commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
    )
    cmm = build_cmm()

    test = cmm.get_encryption_materials(request=mock_request)
    assert test.algorithm == defaults.ALGORITHM_COMMIT_KEY


def test_get_encryption_materials_committing_algorithm_policy_forbids():
    """Tests that a Default Crypto Materials Manager request with policy FORBID_ENCRYPT_ALLOW_DECRYPT cannot
    encrypt using an algorithm that provides commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = True
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    with pytest.raises(ActionNotAllowedError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)

    excinfo.match("Configuration conflict. Cannot encrypt due to .* requiring only non-committed messages")


def test_get_encryption_materials_committing_algorithm_require_encrypt_allow_decrypt(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy REQUIRE_ENCRYPT_ALLOW_DECRYPT can
    successfully encrypt using an algorithm that provides commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = True
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    test = cmm.get_encryption_materials(request=mock_request)
    assert test.algorithm is mock_request.algorithm


def test_get_encryption_materials_committing_algorithm_require_encrypt_require_decrypt(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy REQUIRE_ENCRYPT_REQUIRE_DECRYPT can
    successfully encrypt using an algorithm that provides commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = True
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    test = cmm.get_encryption_materials(request=mock_request)
    assert test.algorithm is mock_request.algorithm


def test_get_encryption_materials_uncommitting_algorithm_policy_forbid(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy FORBID_ENCRYPT_ALLOW_DECRYPT can
    successfully encrypt using an algorithm that does not provide commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = False
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    test = cmm.get_encryption_materials(request=mock_request)
    assert test.algorithm is mock_request.algorithm


def test_get_encryption_materials_uncommitting_algorithm_require_encrypt_allow_decrypt(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy REQUIRE_ENCRYPT_ALLOW_DECRYPT cannot
    encrypt using an algorithm that does not provide commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = False
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    with pytest.raises(ActionNotAllowedError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)
    excinfo.match("Configuration conflict. Cannot encrypt due to .* requiring only committed messages")


def test_get_encryption_materials_uncommitting_algorithm_require_encrypt_require_decrypt(patch_for_dcmm_encrypt):
    """Tests that a Default Crypto Materials Manager request with policy REQUIRE_ENCRYPT_REQUIRE_DECRYPT cannot
    encrypt using an algorithm that does not provide commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = False
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    with pytest.raises(ActionNotAllowedError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)
    excinfo.match("Configuration conflict. Cannot encrypt due to .* requiring only committed messages")


def test_get_encryption_materials_no_mks(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=MagicMock(__class__=Algorithm), encryption_context={})
    cmm = build_cmm()
    cmm.master_key_provider.master_keys_for_encryption.return_value = (None, set([]))

    with pytest.raises(MasterKeyProviderError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)

    excinfo.match(r"No Master Keys available from Master Key Provider")


def test_get_encryption_materials_primary_mk_not_in_mks(patch_for_dcmm_encrypt):
    mock_request = MagicMock(algorithm=MagicMock(__class__=Algorithm), encryption_context={})
    cmm = build_cmm()
    cmm.master_key_provider.master_keys_for_encryption.return_value = (
        sentinel.primary_mk,
        set([sentinel.mk_a, sentinel.mk_b]),
    )

    with pytest.raises(MasterKeyProviderError) as excinfo:
        cmm.get_encryption_materials(request=mock_request)

    excinfo.match(r"Primary Master Key not in provided Master Keys")


def test_load_verification_key_from_encryption_context_key_not_needed_and_not_found():
    cmm = build_cmm()

    test = cmm._load_verification_key_from_encryption_context(
        algorithm=MagicMock(signing_algorithm_info=None), encryption_context={}
    )

    assert test is None


def test_load_verification_key_from_encryption_context_key_is_needed_and_not_found():
    cmm = build_cmm()

    with pytest.raises(SerializationError) as excinfo:
        cmm._load_verification_key_from_encryption_context(
            algorithm=MagicMock(signing_algorithm_info=sentinel.not_none), encryption_context={}
        )

    excinfo.match(r"No signature verification key found in header for signed algorithm.")


def test_load_verification_key_from_encryption_context_key_found_but_not_needed():
    cmm = build_cmm()

    with pytest.raises(SerializationError) as excinfo:
        cmm._load_verification_key_from_encryption_context(
            algorithm=MagicMock(signing_algorithm_info=None),
            encryption_context={ENCODED_SIGNER_KEY: "something that exists"},
        )

    excinfo.match(r"Signature verification key found in header for non-signed algorithm.")


def test_load_verification_key_from_encryption_context_key_is_needed_and_is_found(mocker):
    mock_verifier = MagicMock()
    mocker.patch.object(aws_encryption_sdk.materials_managers.default, "Verifier")
    aws_encryption_sdk.materials_managers.default.Verifier.from_encoded_point.return_value = mock_verifier
    encryption_context = {ENCODED_SIGNER_KEY: sentinel.encoded_verification_key}
    mock_algorithm = MagicMock(signing_algorithm_info=sentinel.not_none)
    cmm = build_cmm()

    test = cmm._load_verification_key_from_encryption_context(
        algorithm=mock_algorithm, encryption_context=encryption_context
    )

    aws_encryption_sdk.materials_managers.default.Verifier.from_encoded_point.assert_called_once_with(
        algorithm=mock_algorithm, encoded_point=sentinel.encoded_verification_key
    )
    assert test is mock_verifier.key_bytes.return_value


@pytest.mark.parametrize("is_committing", (True, False))
def test_decrypt_materials(mocker, patch_for_dcmm_decrypt, is_committing):
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = is_committing
    mock_request = MagicMock(algorithm=mock_alg)
    cmm = build_cmm()

    test = cmm.decrypt_materials(request=mock_request)

    cmm.master_key_provider.decrypt_data_key_from_list.assert_called_once_with(
        encrypted_data_keys=mock_request.encrypted_data_keys,
        algorithm=mock_request.algorithm,
        encryption_context=mock_request.encryption_context,
    )
    cmm._load_verification_key_from_encryption_context.assert_called_once_with(
        algorithm=mock_request.algorithm, encryption_context=mock_request.encryption_context
    )
    assert test.data_key is cmm.master_key_provider.decrypt_data_key_from_list.return_value
    assert test.verification_key == patch_for_dcmm_decrypt


@pytest.mark.parametrize(
    "policy",
    (
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    ),
)
def test_decrypt_materials_committing_alg(patch_for_dcmm_decrypt, policy):
    """Tests that all configurations of CommitmentPolicy are able to decrypt when the algorithm provides commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = True
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = policy

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    test = cmm.decrypt_materials(request=mock_request)

    cmm.master_key_provider.decrypt_data_key_from_list.assert_called_once_with(
        encrypted_data_keys=mock_request.encrypted_data_keys,
        algorithm=mock_request.algorithm,
        encryption_context=mock_request.encryption_context,
    )
    cmm._load_verification_key_from_encryption_context.assert_called_once_with(
        algorithm=mock_request.algorithm, encryption_context=mock_request.encryption_context
    )
    assert test.data_key is cmm.master_key_provider.decrypt_data_key_from_list.return_value
    assert test.verification_key == patch_for_dcmm_decrypt


@pytest.mark.parametrize(
    "policy",
    (
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
    ),
)
def test_decrypt_materials_uncommitting_alg_allow_policies(patch_for_dcmm_decrypt, policy):
    """Tests that all configurations of CommitmentPolicy which allow decryption of un-committed messages are able
    to decrypt when the algorithm does not provide commitment."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = False
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = policy

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    test = cmm.decrypt_materials(request=mock_request)

    cmm.master_key_provider.decrypt_data_key_from_list.assert_called_once_with(
        encrypted_data_keys=mock_request.encrypted_data_keys,
        algorithm=mock_request.algorithm,
        encryption_context=mock_request.encryption_context,
    )
    cmm._load_verification_key_from_encryption_context.assert_called_once_with(
        algorithm=mock_request.algorithm, encryption_context=mock_request.encryption_context
    )
    assert test.data_key is cmm.master_key_provider.decrypt_data_key_from_list.return_value
    assert test.verification_key == patch_for_dcmm_decrypt


def test_decrypt_materials_uncommitting_alg_require_policy(patch_for_dcmm_decrypt):
    """Tests that a configuration which requires commitment does not allow decryption of un-committed messages."""
    mock_alg = MagicMock(__class__=Algorithm)
    mock_alg.is_committing.return_value = False
    mock_request = MagicMock(algorithm=mock_alg, encryption_context={})
    mock_request.commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT

    cmm = DefaultCryptoMaterialsManager(master_key_provider=build_mkp())

    with pytest.raises(ActionNotAllowedError) as excinfo:
        cmm.decrypt_materials(request=mock_request)
    excinfo.match("Configuration conflict. Cannot decrypt due to .* requiring only committed messages.")
