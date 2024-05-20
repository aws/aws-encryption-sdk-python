# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test suite for `aws_encryption_sdk`."""
import io
import logging

import pytest
from botocore.exceptions import BotoCoreError

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import (
    ActionNotAllowedError,
    CustomMaximumValueExceeded,
    DecryptKeyError,
    EncryptKeyError,
    MasterKeyProviderError,
)
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX, Algorithm, CommitmentPolicy
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryAwsKmsMasterKeyProvider,
    DiscoveryFilter,
    KMSMasterKey,
    StrictAwsKmsMasterKeyProvider,
)

from .integration_test_utils import (
    get_cmk_arn,
    setup_kms_master_key_provider,
    setup_kms_master_key_provider_with_botocore_session,
    setup_kms_master_key_provider_with_duplicate_keys,
)

pytestmark = [pytest.mark.integ]


VALUES = {
    "plaintext_128": (
        b"\xa3\xf6\xbc\x89\x95\x15(\xc8}\\\x8d=zu^{JA\xc1\xe9\xf0&m\xe6TD\x03"
        b"\x165F\x85\xae\x96\xd9~ \xa6\x13\x88\xf8\xdb\xc9\x0c\xd8\xd8\xd4\xe0"
        b"\x02\xe9\xdb+\xd4l\xeaq\xf6\xba.cg\xda\xe4V\xd9\x9a\x96\xe8\xf4:\xf5"
        b"\xfd\xd7\xa6\xfa\xd1\x85\xa7o\xf5\x94\xbcE\x14L\xa1\x87\xd9T\xa6\x95"
        b"eZVv\xfe[\xeeJ$a<9\x1f\x97\xe1\xd6\x9dQc\x8b7n\x0f\x1e\xbd\xf5\xba"
        b"\x0e\xae|%\xd8L]\xa2\xa2\x08\x1f"
    ),
    "encryption_context": {"key_a": "value_a", "key_b": "value_b", "key_c": "value_c"},
}


def test_encrypt_verify_user_agent_kms_master_key_provider(caplog):
    caplog.set_level(level=logging.DEBUG)
    mkp = setup_kms_master_key_provider()
    mk = mkp.master_key(get_cmk_arn())

    mk.generate_data_key(algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context={})

    assert USER_AGENT_SUFFIX in caplog.text


def test_encrypt_verify_user_agent_kms_master_key(caplog):
    caplog.set_level(level=logging.DEBUG)
    mk = KMSMasterKey(key_id=get_cmk_arn())

    mk.generate_data_key(algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context={})

    assert USER_AGENT_SUFFIX in caplog.text


def test_remove_bad_client():
    test = setup_kms_master_key_provider(False)
    test.add_regional_client("us-fakey-12")

    with pytest.raises(BotoCoreError):
        test._regional_clients["us-fakey-12"].list_keys()

    assert "us-fakey-12" not in test._regional_clients


def test_regional_client_does_not_modify_botocore_session(caplog):
    mkp = setup_kms_master_key_provider_with_botocore_session()
    fake_region = "us-fakey-12"

    assert mkp.config.botocore_session.get_config_variable("region") != fake_region
    mkp.add_regional_client(fake_region)
    assert mkp.config.botocore_session.get_config_variable("region") != fake_region


class TestKMSThickClientIntegration(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        self.kms_master_key_provider = setup_kms_master_key_provider()

    def test_encryption_cycle_default_algorithm_framed_stream(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a framed message using the default algorithm.
        """
        with aws_encryption_sdk.EncryptionSDKClient().stream(
            source=io.BytesIO(VALUES["plaintext_128"]),
            key_provider=self.kms_master_key_provider,
            mode="e",
            encryption_context=VALUES["encryption_context"],
        ) as encryptor:
            ciphertext = encryptor.read()
        header_1 = encryptor.header
        with aws_encryption_sdk.EncryptionSDKClient().stream(
            source=io.BytesIO(ciphertext), key_provider=self.kms_master_key_provider, mode="d"
        ) as decryptor:
            plaintext = decryptor.read()
        header_2 = decryptor.header
        assert plaintext == VALUES["plaintext_128"]
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_framed_stream_many_lines(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a framed message with many frames using the default algorithm.
        """
        ciphertext = b""
        with aws_encryption_sdk.EncryptionSDKClient().stream(
            source=io.BytesIO(VALUES["plaintext_128"] * 10),
            key_provider=self.kms_master_key_provider,
            mode="e",
            encryption_context=VALUES["encryption_context"],
            frame_length=128,
        ) as encryptor:
            for chunk in encryptor:
                ciphertext += chunk
        header_1 = encryptor.header
        plaintext = b""
        with aws_encryption_sdk.EncryptionSDKClient().stream(
            source=io.BytesIO(ciphertext), key_provider=self.kms_master_key_provider, mode="d"
        ) as decryptor:
            for chunk in decryptor:
                plaintext += chunk
        header_2 = decryptor.header
        assert plaintext == VALUES["plaintext_128"] * 10
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a non-framed message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
        )
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_default_algorithm_non_framed_no_encryption_context(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a non-framed message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"], key_provider=self.kms_master_key_provider, frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_default_algorithm_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a single frame message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_default_algorithm_multiple_frames(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a framed message with multiple frames using the
        default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"] * 100,
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES["plaintext_128"] * 100

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a single frame message using the aes_128_gcm_iv12_tag16
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a non-framed message using the aes_128_gcm_iv12_tag16
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a single frame message using the aes_192_gcm_iv12_tag16
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a non-framed message using the aes_192_gcm_iv12_tag16
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a single frame message using the aes_256_gcm_iv12_tag16
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
        for a non-framed message using the aes_256_gcm_iv12_tag16
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
        single frame message using the aes_128_gcm_iv12_tag16_hkdf_sha256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
        non-framed message using the aes_128_gcm_iv12_tag16_hkdf_sha256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
        single frame message using the aes_192_gcm_iv12_tag16_hkdf_sha256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
        non-framed message using the aes_192_gcm_iv12_tag16_hkdf_sha256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
        single frame message using the aes_256_gcm_iv12_tag16_hkdf_sha256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
        non-framed message using the aes_256_gcm_iv12_tag16_hkdf_sha256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        frame message using the aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        block message using the aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        frame message using the aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        block message using the aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        frame message using the aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        block message using the aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_hkdf_sha512_commit_key_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        frame message using the aes_256_gcm_hkdf_sha512_commit_key algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        )
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_hkdf_sha512_commit_key_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        block message using the aes_256_gcm_hkdf_sha512_commit_key algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        )
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        frame message using the aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        )
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
        block message using the aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384
        algorithm.
        """
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        )
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
        )
        plaintext, _ = client.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_decrypt_success_strict_matching_key_id(self):
        """Test that a Strict KMS Master Key Provider can successfully
        decrypt an EDK when it has been configured with the correct key id
        """
        cmk_arn = get_cmk_arn()
        provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_decrypt_failure_strict_mismatched_key_id(self):
        """Test that a Strict KMS Master Key Provider fails to decrypt an
        EDK when it has not been configured with the correct key id
        """
        cmk_arn = get_cmk_arn()
        encrypt_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=encrypt_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        # Check that we can decrypt the ciphertext using the original provider
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=encrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

        # Check that we cannot decrypt the ciphertext using a non-discovery provider without the correct key_id
        second_cmk_arn = cmk_arn + "-doesnotexist"
        decrypt_provider = StrictAwsKmsMasterKeyProvider(key_ids=[second_cmk_arn])

        with pytest.raises(DecryptKeyError) as excinfo:
            aws_encryption_sdk.EncryptionSDKClient().decrypt(source=ciphertext, key_provider=decrypt_provider)
        excinfo.match("Unable to decrypt any data key")

    def test_decrypt_success_discovery_no_filter(self):
        """Test that a Discovery KMS Master Key Provider in unfiltered discovery mode can
        decrypt a valid EDK.
        """
        cmk_arn = get_cmk_arn()
        encrypt_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=encrypt_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        # Check that we can decrypt the ciphertext using the original provider
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=encrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

        # Check that we can decrypt the ciphertext using a discovery provider with no filter
        decrypt_provider = DiscoveryAwsKmsMasterKeyProvider()

        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=decrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_decrypt_success_discovery_filter(self):
        """Test that a Discovery KMS Master Key Provider in filtered discovery mode can
        decrypt a ciphertext when it is configured with the correct account id and partition.
        """
        cmk_arn = get_cmk_arn()
        encrypt_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=encrypt_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        # Check that we can decrypt the ciphertext using the original provider
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=encrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

        # Check that we can decrypt the ciphertext using a discovery provider that allows this account and partition
        arn = arn_from_str(cmk_arn)
        discovery_filter = DiscoveryFilter(partition=arn.partition, account_ids=[arn.account_id])
        decrypt_provider = DiscoveryAwsKmsMasterKeyProvider(discovery_filter=discovery_filter)

        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=decrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_decrypt_failure_discovery_disallowed_account(self):
        """Test that a KMS Master Key Provider in filtered discovery mode fails to
        decrypt an EDK if the EDK was wrapped by a KMS Master Key in an
        AWS account that is not allowed by the filter.
        """
        cmk_arn = get_cmk_arn()
        encrypt_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=encrypt_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        # Check that we can decrypt the ciphertext using the original provider
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=encrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

        # Check that we cannot decrypt the ciphertext using a discovery provider that does not match this key's account
        arn = arn_from_str(cmk_arn)
        discovery_filter = DiscoveryFilter(partition=arn.partition, account_ids=["99"])
        decrypt_provider = DiscoveryAwsKmsMasterKeyProvider(discovery_filter=discovery_filter)

        with pytest.raises(MasterKeyProviderError) as excinfo:
            aws_encryption_sdk.EncryptionSDKClient().decrypt(source=ciphertext, key_provider=decrypt_provider)
        excinfo.match("not allowed by this Master Key Provider")

    def test_decrypt_failure_discovery_disallowed_partition(self):
        """Test that a KMS Master Key Provider in filtered discovery mode fails to
        decrypt an EDK if the EDK was wrapped by a KMS Master Key in an
        AWS partition that is not allowed by the filter.
        """
        cmk_arn = get_cmk_arn()
        encrypt_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=encrypt_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        # Check that we can decrypt the ciphertext using the original provider
        plaintext, _ = aws_encryption_sdk.EncryptionSDKClient().decrypt(
            source=ciphertext, key_provider=encrypt_provider
        )
        assert plaintext == VALUES["plaintext_128"]

        # Check that we cannot decrypt the ciphertext using a discovery provider that does not match this key's
        # partition
        arn = arn_from_str(cmk_arn)
        discovery_filter = DiscoveryFilter(partition="aws-cn", account_ids=[arn.account_id])
        decrypt_provider = DiscoveryAwsKmsMasterKeyProvider(discovery_filter=discovery_filter)

        with pytest.raises(MasterKeyProviderError) as excinfo:
            aws_encryption_sdk.EncryptionSDKClient().decrypt(source=ciphertext, key_provider=decrypt_provider)
        excinfo.match("not allowed by this Master Key Provider")

    def test_encrypt_failure_unknown_cmk(self):
        """Test that a Master Key Provider returns the correct error when one of the
        keys with which it was configured is unable to encrypt
        """
        cmk_arn = get_cmk_arn()
        second_cmk_arn = cmk_arn + "-doesnotexist"
        provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn, second_cmk_arn])

        with pytest.raises(EncryptKeyError) as excinfo:
            aws_encryption_sdk.EncryptionSDKClient().encrypt(
                source=VALUES["plaintext_128"],
                key_provider=provider,
                encryption_context=VALUES["encryption_context"],
                frame_length=1024,
            )
        excinfo.match("Master Key {key_id} unable to encrypt".format(key_id=second_cmk_arn))

    def test_encrypt_failure_discovery_provider(self):
        """Test that a Discovery Master Key Provider cannot encrypt"""
        provider = DiscoveryAwsKmsMasterKeyProvider()

        with pytest.raises(MasterKeyProviderError) as excinfo:
            aws_encryption_sdk.EncryptionSDKClient().encrypt(
                source=VALUES["plaintext_128"],
                key_provider=provider,
                encryption_context=VALUES["encryption_context"],
                frame_length=1024,
            )
        excinfo.match("No Master Keys available from Master Key Provider")

    def test_decrypt_unsigned_success_unsigned_message(self):
        """Test that "decrypt-unsigned" mode accepts unsigned messages."""
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        with aws_encryption_sdk.EncryptionSDKClient().stream(
            source=io.BytesIO(ciphertext), key_provider=self.kms_master_key_provider, mode="decrypt-unsigned"
        ) as decryptor:
            plaintext = decryptor.read()
            assert plaintext == VALUES["plaintext_128"]

    def test_decrypt_unsigned_failure_signed_message(self):
        """Test that "decrypt-unsigned" mode rejects signed messages."""
        ciphertext, _ = aws_encryption_sdk.EncryptionSDKClient().encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )

        with aws_encryption_sdk.EncryptionSDKClient().stream(
            source=io.BytesIO(ciphertext), key_provider=self.kms_master_key_provider, mode="decrypt-unsigned"
        ) as decryptor:
            with pytest.raises(ActionNotAllowedError) as excinfo:
                decryptor.read()
            excinfo.match("Configuration conflict. Cannot decrypt signed message in decrypt-unsigned mode.")

    @pytest.mark.parametrize("num_keys", (2, 3))
    def test_encrypt_cycle_within_max_encrypted_data_keys(self, num_keys):
        """Test that the client can encrypt and decrypt messages with fewer
        EDKs than the configured max."""
        provider = setup_kms_master_key_provider_with_duplicate_keys(num_keys)
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            max_encrypted_data_keys=3,
        )
        ciphertext, _ = client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=provider,
        )
        plaintext, _ = client.decrypt(
            source=ciphertext,
            key_provider=provider,
        )
        assert plaintext == VALUES["plaintext_128"]

    def test_encrypt_over_max_encrypted_data_keys(self):
        """Test that the client refuses to encrypt when too many EDKs are provided."""
        provider = setup_kms_master_key_provider_with_duplicate_keys(4)
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            max_encrypted_data_keys=3,
        )
        with pytest.raises(CustomMaximumValueExceeded) as exc_info:
            _, _ = client.encrypt(
                source=VALUES["plaintext_128"],
                key_provider=provider,
            )
        exc_info.match("Number of encrypted data keys found larger than configured value")

    def test_decrypt_over_max_encrypted_data_keys(self):
        """Test that the client refuses to decrypt a message with too many EDKs."""
        provider = setup_kms_master_key_provider_with_duplicate_keys(4)
        encrypt_client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        )
        ciphertext, _ = encrypt_client.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=provider,
        )
        decrypt_client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            max_encrypted_data_keys=3,
        )
        with pytest.raises(CustomMaximumValueExceeded) as exc_info:
            _, _ = decrypt_client.decrypt(
                source=ciphertext,
                key_provider=provider,
            )
        exc_info.match("Number of encrypted data keys found larger than configured value")
