# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test suite for `aws_encryption_sdk`."""
import io
import logging

import pytest
from botocore.exceptions import BotoCoreError

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX, Algorithm
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyProvider

from .integration_test_utils import (
    get_cmk_arn,
    setup_kms_master_key_provider,
    setup_kms_master_key_provider_with_botocore_session,
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
    test = KMSMasterKeyProvider()
    fake_region = "us-fakey-12"
    test.add_regional_client(fake_region)

    with pytest.raises(BotoCoreError):
        test._regional_clients[fake_region].list_keys()

    assert fake_region not in test._regional_clients


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
        with aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES["plaintext_128"]),
            key_provider=self.kms_master_key_provider,
            mode="e",
            encryption_context=VALUES["encryption_context"],
        ) as encryptor:
            ciphertext = encryptor.read()
        header_1 = encryptor.header
        with aws_encryption_sdk.stream(
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
        with aws_encryption_sdk.stream(
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
        with aws_encryption_sdk.stream(
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
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_default_algorithm_non_framed_no_encryption_context(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a non-framed message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"], key_provider=self.kms_master_key_provider, frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_default_algorithm_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_default_algorithm_multiple_frames(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a framed message with multiple frames using the
            default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"] * 100,
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"] * 100

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the aes_128_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a non-framed message using the aes_128_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the aes_192_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a non-framed message using the aes_192_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the aes_256_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a non-framed message using the aes_256_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single frame message using the aes_128_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            non-framed message using the aes_128_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single frame message using the aes_192_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            non-framed message using the aes_192_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single frame message using the aes_256_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            non-framed message using the aes_256_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            frame message using the aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            block message using the aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            frame message using the aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            block message using the aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            frame message using the aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_non_framed(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            block message using the aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES["plaintext_128"],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES["encryption_context"],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        )
        plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=self.kms_master_key_provider)
        assert plaintext == VALUES["plaintext_128"]
