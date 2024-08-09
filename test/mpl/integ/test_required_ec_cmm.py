# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import copy

import pytest
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import (
    CreateDefaultCryptographicMaterialsManagerInput,
    CreateRequiredEncryptionContextCMMInput,
)

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError

from ..utils import TestEncryptionContexts, TestKeyringCreator

pytestmark = [pytest.mark.integ]

# ESDK client. Used to encrypt/decrypt in each test.
client = aws_encryption_sdk.EncryptionSDKClient()

# MPL client. Used to create keyrings.
mpl_client: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
    config=MaterialProvidersConfig()
)


# Keyrings under test
SOME_RSA_KEYRING = TestKeyringCreator._create_raw_rsa_keyring()
SOME_AES_KEYRING = TestKeyringCreator._create_raw_aes_keyring()
SOME_KMS_KEYRING = TestKeyringCreator._create_kms_keyring()
SOME_HIERARCHICAL_KEYRING = TestKeyringCreator._create_hierarchical_keyring()
TEST_KEYRINGS_LIST = [
    SOME_AES_KEYRING,
    SOME_KMS_KEYRING,
    SOME_RSA_KEYRING,
    SOME_HIERARCHICAL_KEYRING,
]
# Multi-keyring composed of individual keyrings.
# In lots of tests in this file,
# this multi keyring encrypts one message,
# then the test attempts decryption with all of its component keyrings
# ("component" = generator + child keyrings).
SOME_MULTI_KEYRING = TestKeyringCreator._create_multi_keyring(TEST_KEYRINGS_LIST)


SOME_PLAINTEXT = b"Hello World"


@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.ALL_ENCRYPTION_CONTEXTS)
# HAPPY CASE 1
# Test supply same encryption context on encrypt and decrypt NO filtering
def test_GIVEN_same_EC_on_encrypt_and_decrypt_WHEN_encrypt_decrypt_cycle_THEN_decrypt_matches_plaintext(
    encryption_context
):
    # When: encrypt/decrypt cycle
    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        keyring=SOME_MULTI_KEYRING,
        # Given: same encryption context on encrypt and decrypt
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        pt, _ = client.decrypt(
            source=ct,
            # Given: same encryption context on encrypt and decrypt
            encryption_context=encryption_context,
            keyring=decrypt_keyring
        )

        # Then: decrypted plaintext matches original plaintext
        assert pt == SOME_PLAINTEXT


# This test needs >=1 item to supply as required encryption context
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.NONEMPTY_ENCRYPTION_CONTEXTS)
# HAPPY CASE 2
# On Encrypt we will only write one encryption context key value to the header
# we will then supply only what we didn't write wth no required ec cmm,
# This test case is checking that the default cmm is doing the correct filtering
def test_GIVEN_RECCMM_with_one_REC_key_on_encrypt_AND_default_CMM_with_valid_reproduced_EC_on_decrypt_WHEN_supply_reproduced_EC_with_REC_key_on_decrypt_THEN_decrypt_matches_plaintext( # noqa pylint: disable=line-too-long
    encryption_context
):
    # Grab one item from encryption_context to supply as reproduced EC
    one_k, one_v = next(iter(encryption_context.items()))
    reproduced_ec = {one_k: one_v}
    # Given: one required encryption context (REC) key
    required_ec_keys = [one_k]

    default_cmm = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    required_ec_cmm = mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm,
            # Given: one required encryption context (REC) key
            required_encryption_context_keys=required_ec_keys
        )
    )

    # When: encrypt/decrypt cycle
    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        # Given: required encryption context CMM (RECCMM) on encrypt
        materials_manager=required_ec_cmm,
        # Given: encryption context with REC key on encrypt
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        pt, _ = client.decrypt(
            source=ct,
            # Given: default CMM on decrypt (ESDK auto-creates default CMM)
            keyring=decrypt_keyring,
            # When: supply valid reproduced EC (containing REC key) on decrypt
            encryption_context=reproduced_ec,
        )

        # Then: decrypted plaintext matches original plaintext, no errors
        assert pt == SOME_PLAINTEXT


# This test needs >=1 item to supply as required encryption context
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.NONEMPTY_ENCRYPTION_CONTEXTS)
# HAPPY CASE 3
# On Encrypt we will only write one encryption context key value to the header
# we will then supply only what we didn't write but included in the signature while we
# are configured with the required encryption context cmm
def test_GIVEN_RECCMM_with_one_REC_key_on_encrypt_AND_RECCMM_with_valid_reproduced_EC_on_decrypt_WHEN_supply_reproduced_EC_with_REC_key_on_decrypt_THEN_decrypt_matches_plaintext( # noqa pylint: disable=line-too-long
    encryption_context
):
    # Grab one item from encryption_context to supply as reproduced EC
    one_k, one_v = next(iter(encryption_context.items()))
    reproduced_ec = {one_k: one_v}
    # Given: one required encryption context (REC) key
    required_ec_keys = [one_k]

    default_cmm_encrypt = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    required_ec_cmm_encrypt = mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm_encrypt,
            # Given: one required encryption context (REC) key
            required_encryption_context_keys=required_ec_keys
        )
    )

    # When: encrypt/decrypt cycle
    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        # Given: required encryption context CMM (RECCMM) on encrypt
        materials_manager=required_ec_cmm_encrypt,
        # Given: encryption context with REC key on encrypt
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        default_cmm_decrypt = mpl_client.create_default_cryptographic_materials_manager(
            CreateDefaultCryptographicMaterialsManagerInput(
                keyring=decrypt_keyring,
            )
        )

        required_ec_cmm_decrypt = mpl_client.create_required_encryption_context_cmm(
            CreateRequiredEncryptionContextCMMInput(
                # Given: required encryption context CMM (RECCMM) on decrypt
                underlying_cmm=default_cmm_decrypt,
                # Given: correct required encryption context (REC) keys on decrypt
                required_encryption_context_keys=required_ec_keys
            )
        )

        pt, _ = client.decrypt(
            source=ct,
            # Given: required encryption context CMM (RECCMM) on decrypt
            materials_manager=required_ec_cmm_decrypt,
            # When: supply reproduced EC on decrypt
            encryption_context=reproduced_ec,
        )

        # Then: decrypted plaintext matches original plaintext
        assert pt == SOME_PLAINTEXT


# This test needs >=1 item to supply as required encryption context
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.NONEMPTY_ENCRYPTION_CONTEXTS)
# HAPPY CASE 4
# On Encrypt we write all encryption context
# as if the message was encrypted before the feature existed.
# We will then have a required encryption context cmm
# that will require us to supply the encryption context on decrypt.
def test_GIVEN_default_CMM_on_encrypt_AND_default_CMM_with_valid_reproduced_EC_on_decrypt_WHEN_supply_reproduced_EC_with_REC_key_on_decrypt_THEN_decrypt_matches_plaintext( # noqa pylint: disable=line-too-long
    encryption_context
):
    # Grab one item from encryption_context to supply as reproduced EC
    one_k, one_v = next(iter(encryption_context.items()))
    reproduced_ec = {one_k: one_v}
    # Given: one required encryption context (REC) key
    required_ec_keys = [one_k]

    default_cmm_encrypt = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    # When: encrypt/decrypt cycle
    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        # Given: default CMM on encrypt
        materials_manager=default_cmm_encrypt,
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        default_cmm_decrypt = mpl_client.create_default_cryptographic_materials_manager(
            CreateDefaultCryptographicMaterialsManagerInput(
                keyring=decrypt_keyring,
            )
        )

        required_ec_cmm_decrypt = mpl_client.create_required_encryption_context_cmm(
            CreateRequiredEncryptionContextCMMInput(
                underlying_cmm=default_cmm_decrypt,
                # Given: one required encryption context (REC) key
                required_encryption_context_keys=required_ec_keys
            )
        )

        pt, _ = client.decrypt(
            source=ct,
            # Given: required encryption context CMM (RECCMM) on decrypt
            materials_manager=required_ec_cmm_decrypt,
            # When: supply reproduced EC on decrypt
            encryption_context=reproduced_ec,
        )

        # Then: decrypted plaintext matches original plaintext
        assert pt == SOME_PLAINTEXT

# This test needs >=2 items in EC so it can swap their key/value pairs
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.AT_LEAST_TWO_ITEMS_ENCRYPTION_CONTEXTS)
# FAILURE CASE 1
# Encrypt with and store all encryption context in header
# On Decrypt supply additional encryption context not stored in the header; this MUST fail
# On Decrypt supply mismatched encryption context key values; this MUST fail
def test_GIVEN_default_CMM_with_EC_on_encrypt_AND_default_CMM_with_different_EC_on_decrypt_WHEN_decrypt_THEN_raise_AWSEncryptionSDKClientError( # noqa pylint: disable=line-too-long
    encryption_context,
):
    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        keyring=SOME_MULTI_KEYRING,
        encryption_context=encryption_context,
    )

    # Create some different ECs to test failure on decrypt

    # Swap one key/value pair to create a "mismatched" EC
    ec_iter = iter(encryption_context.items())
    one_k, one_v = next(ec_iter)
    two_k, two_v = next(ec_iter)
    some_mismatched_ec = copy.deepcopy(encryption_context)
    some_mismatched_ec[one_k] = two_v
    some_mismatched_ec[two_k] = one_v

    # Some other encryption context where its key/value pair is not in the encryption context on encrypt
    some_reproduced_ec_not_in_ec = {"this is not in": "the original encryption context"}

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        # Then: decrypting with mismatched EC raises AWSEncryptionSDKClientError
        with pytest.raises(AWSEncryptionSDKClientError):
            # When: decrypt
            client.decrypt(
                source=ct,
                keyring=decrypt_keyring,
                # Given: different encryption context on decrypt
                encryption_context=some_mismatched_ec,
            )

        # Then: decrypting with some other EC raises AWSEncryptionSDKClientError
        with pytest.raises(AWSEncryptionSDKClientError):
            # When: decrypt
            client.decrypt(
                source=ct,
                keyring=decrypt_keyring,
                # Given: different encryption context on decrypt
                encryption_context=some_reproduced_ec_not_in_ec,
            )


# This test needs >=1 item to supply as required encryption context
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.NONEMPTY_ENCRYPTION_CONTEXTS)
# FAILURE CASE 2
# Encrypt will not store all Encryption Context, we will drop one entry but it will still get
# included in the
# header signture.
# Decrypt will not supply any reproduced Encryption Context; this MUST fail.
def test_GIVEN_RECCCMM_with_one_REC_key_on_encrypt_AND_default_CMM_with_no_EC_on_decrypt_WHEN_decrypt_THEN_raise_AWSEncryptionSDKClientError( # noqa pylint: disable=line-too-long
    encryption_context,
):
    # Grab one item from encryption_context to supply as reproduced EC
    one_k, _ = next(iter(encryption_context.items()))
    # Given: one required encryption context (REC) key
    required_ec_keys = [one_k]

    default_cmm_encrypt = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    required_ec_cmm_encrypt = mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm_encrypt,
            # Given: one required encryption context (REC) key
            required_encryption_context_keys=required_ec_keys
        )
    )

    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        materials_manager=required_ec_cmm_encrypt,
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        # Then: decrypting with no EC raises AWSEncryptionSDKClientError
        with pytest.raises(AWSEncryptionSDKClientError):
            # When: decrypt
            client.decrypt(
                source=ct,
                keyring=decrypt_keyring,
                # Given: no encryption context on decrypt
            )


# This test needs >=1 item to supply as required encryption context
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.NONEMPTY_ENCRYPTION_CONTEXTS)
# FAILURE CASE 3
# Encrypt will not store all Encryption Context, we will drop one entry but it will still get
# included in the
# header signture.
# Decrypt will supply the correct key but incorrect value; this MUST fail.
def test_GIVEN_RECCMM_on_encrypt_AND_EC_with_wrong_value_for_key_on_decrypt_WHEN_decrypt_THEN_raise_AWSEncryptionSDKClientError( # noqa pylint: disable=line-too-long
    encryption_context,
):
    # Grab one item from encryption_context to supply as reproduced EC
    one_k, _ = next(iter(encryption_context.items()))
    # Given: one required encryption context (REC) key
    required_ec_keys = [one_k]
    # Create mismatched EC
    some_mismatched_ec = copy.deepcopy(encryption_context)
    some_mismatched_ec[one_k] = "some incorrect value NOT in the original encryption context"

    default_cmm_encrypt = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    required_ec_cmm_encrypt = mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm_encrypt,
            required_encryption_context_keys=required_ec_keys
        )
    )

    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        materials_manager=required_ec_cmm_encrypt,
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        # Then: decrypting with mismatched EC raises AWSEncryptionSDKClientError
        with pytest.raises(AWSEncryptionSDKClientError):
            # When: decrypt
            client.decrypt(
                source=ct,
                keyring=decrypt_keyring,
                # Given: encryption context with wrong value for required key on decrypt
                encryption_context=some_mismatched_ec,
            )


# This test needs >=2 items in EC so it create incorrect reproduced EC scenarios
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.AT_LEAST_TWO_ITEMS_ENCRYPTION_CONTEXTS)
# FAILURE CASE 4
# Encrypt will not store all Encryption Context, we will drop one entry but it will still get
# included in the
# header signture.
# Decrypt will supply the correct key but incorrect value; this MUST fail.
def test_GIVEN_RECCMM_on_encrypt_AND_reproduced_EC_missing_REC_key_on_decrypt_WHEN_decrypt_THEN_raise_AWSEncryptionSDKClientError( # noqa pylint: disable=line-too-long
    encryption_context,
):
    # Grab one item from encryption_context to supply as reproduced EC
    ec_iter = iter(encryption_context.items())
    required_k, _ = next(ec_iter)
    required_ec_keys = [required_k]
    # Grab another item to use as the reproduced EC
    # where the key in reproduced EC is not in required encryption context keys
    some_other_k, some_other_v = next(ec_iter)
    incorrect_reproduced_ec = {some_other_k : some_other_v}

    default_cmm_encrypt = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    required_ec_cmm_encrypt = mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm_encrypt,
            required_encryption_context_keys=required_ec_keys
        )
    )

    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        materials_manager=required_ec_cmm_encrypt,
        encryption_context=encryption_context,
    )

    for decrypt_keyring in TEST_KEYRINGS_LIST:
        # Then: decrypting with invalid EC raises AWSEncryptionSDKClientError
        with pytest.raises(AWSEncryptionSDKClientError):
            # When: decrypt
            client.decrypt(
                source=ct,
                keyring=decrypt_keyring,
                # Given: encryption context on decrypt does not have required EC key
                encryption_context=incorrect_reproduced_ec,
            )


@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.ALL_ENCRYPTION_CONTEXTS)
# FAILURE CASE 5
# Although we are requesting that we remove a RESERVED key word from the encryption context
# The CMM instantiation will still succeed because the CMM is meant to work with different
# higher level
# encryption libraries who may have different reserved keys. Encryption will ultimately fail.
def test_GIVEN_RECCMM_with_reserved_key_on_encrypt_WHEN_encrypt_THEN_raise_AWSEncryptionSDKClientError(
    encryption_context
):
    invalid_encryption_context = copy.deepcopy(encryption_context)
    # Add reserved EC item to encryption context to make it invalid
    reserved_ec_keyword = "aws-crypto-public-key"
    invalid_encryption_context[reserved_ec_keyword] = "some value in reserved key"
    required_ec_keys = [reserved_ec_keyword]

    default_cmm_encrypt = mpl_client.create_default_cryptographic_materials_manager(
        CreateDefaultCryptographicMaterialsManagerInput(
            keyring=SOME_MULTI_KEYRING,
        )
    )

    required_ec_cmm_encrypt = mpl_client.create_required_encryption_context_cmm(
        CreateRequiredEncryptionContextCMMInput(
            underlying_cmm=default_cmm_encrypt,
            # Given: required encryption context keys has a reserved value
            required_encryption_context_keys=required_ec_keys
        )
    )

    # Then: encrypting with reserved key in encryption context raises AWSEncryptionSDKClientError
    with pytest.raises(AWSEncryptionSDKClientError):
        # When: encrypt
        client.encrypt(
            source=SOME_PLAINTEXT,
            materials_manager=required_ec_cmm_encrypt,
            encryption_context=invalid_encryption_context,
        )


# This test needs >=2 items in EC so it create invalid reproduced EC scenarios
@pytest.mark.parametrize("encryption_context", TestEncryptionContexts.AT_LEAST_TWO_ITEMS_ENCRYPTION_CONTEXTS)
@pytest.mark.parametrize("keyring", TEST_KEYRINGS_LIST)
def test_GIVEN_some_keyring_AND_some_EC_WHEN_decrypt_valid_message_with_mutated_EC_THEN_decryption_matches_expected_result( # noqa pylint: disable=line-too-long
    keyring,
    encryption_context,
):
    # Additional EC
    some_additional_ec = copy.deepcopy(encryption_context)
    some_additional_ec["some extra key to add"] = "some extra value added"

    # Mismatched EC. Swap key/value pair to create a mismatched EC
    ec_iter = iter(encryption_context.items())
    one_k, one_v = next(ec_iter)
    two_k, two_v = next(ec_iter)
    some_mismatched_ec = copy.deepcopy(encryption_context)
    some_mismatched_ec[one_k] = two_v
    some_mismatched_ec[two_k] = one_v

    ct, _ = client.encrypt(
        source=SOME_PLAINTEXT,
        # Given: some keyring
        keyring=keyring,
        # Given: some encryption context
        encryption_context=encryption_context,
    )

    # Expected failure: incorrect EC

    # Then: decrypting with incorrect EC raises AWSEncryptionSDKClientError
    with pytest.raises(AWSEncryptionSDKClientError):
        # When: decrypt
        client.decrypt(
            source=ct,
            keyring=keyring,
            # Given: incorrect encryption context with an extra item
            encryption_context=some_additional_ec,
        )

    # Expected failure: Mismatched EC (swapped value for 2 keys)

    # Then: decrypting with mismatched EC raises AWSEncryptionSDKClientError
    with pytest.raises(AWSEncryptionSDKClientError):
        # When: decrypt
        client.decrypt(
            source=ct,
            keyring=keyring,
            # Given: mismatched encryption context on decrypt
            encryption_context=some_mismatched_ec,
        )

    # Expected success: No encryption context supplied on decrypt
    # (Success because the message was not encrypted with required EC CMM)

    # When: decrypt
    pt, _ = client.decrypt(
        source=ct,
        keyring=keyring,
        # Given: no encryption context on decrypt
    )

    # Then: decrypted plaintext matches original plaintext
    assert pt == SOME_PLAINTEXT

    # Expected success: Correct encryption context supplied on decrypt

    # When: decrypt
    pt, _ = client.decrypt(
        source=ct,
        keyring=keyring,
        # Given: no encryption context on decrypt
        encryption_context=encryption_context,
    )

    # Then: decrypted plaintext matches original plaintext
    assert pt == SOME_PLAINTEXT
