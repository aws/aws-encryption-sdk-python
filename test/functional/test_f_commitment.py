# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional test suite for functionality related to key commitment."""
from test.functional.test_f_aws_encryption_sdk_client import fake_kms_key_provider

import attr
import pytest
import six

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import ActionNotAllowedError, MasterKeyProviderError
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

pytestmark = [pytest.mark.functional, pytest.mark.local]

VALUES = {
    "ciphertext_v2_good_commitment": six.b(
        "\x02\x04xM\xfb\xd11M\x9dU\x92[\x81r2\xc5\xe3mn>^#\x0f\x01\x890\xe2\xc2\xc1\xf2C\xf6}\xc1y\x00\x00\x00\x01"
        "\x00\x0cProviderName\x00\x19KeyId\x00\x00\x00\x80\x00\x00\x00\x0c\xf8\xe6\xc77p;\xc9g\xb0\xf8?{"
        "\x000\xa1;w\xfc<\xce$-\xd8-*\x1e\xcc\xb5B\xed\x84\xda\xafvx\x81\x84\xfeB\xe7\x17\xf64\xd3q\xca\xbd<q\xef\x1b"
        "\xf6f\xff7b\xe3\x9d\xc0s\x0b\xe5\x02\x00\x00\x10\x00\x17\xcf\x08\xf73\xdbQ\x04\x9f:\\\xcb^\xff\xae!\x8d\xbe"
        "\x9b\xf1:\x8fc\xcc\xb1\xb8\x1e\x1dQ\xff/L\x0b\xa9\tX\xfb\x90\x8b\xd3=\xf1\x9c\xd3\x8c!\x96\x9e\xff\xff\xff"
        "\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0eI\x90J\x1ctiO\x05\xce"
        "\x154\x15\x19\xaaW^>B\xc1pL\xa2\xe0A\xda\xe7\x1a \x95f"
    ),
    "ciphertext_v2_bad_commitment": six.b(
        "\x02\x04xo_\xfb\xdd~D\xac\x82\xe9\x8fF\x92@\x8cz\xc0\xd9\xc7,"
        "G\r/\x13\xf3\x03I\xba\xbd\x84k\xee@\x00\x00\x00\x01\x00\x0cProviderName\x00\x19KeyId\x00\x00\x00\x80\x00\x00"
        "\x00\x0c\xa9&e\xf0\xca,\xd4\xaf\x7f\xe9\xca\xf2\x000r\xd4\xfe.F\x85\x99Fk'\x98\x0b\x9c?\n5("
        "o!\xb07\x84)x\xc0t^\x93C\x1934\x7fVq\xefex\xb8\xcd\x87\xe7\x03#\xcb\xf8f\xdb\x02\x00\x00\x10\x00\x00\x01\x02"
        "\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
        "\x1f\xe9@\xcd\x95J\xf9b\xcfd \x8b\x92Y\x7fkZ\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x01\x00\x00\x00\rK\x82\x1d\xe3\xe7U\x1e\x13\xeb\xbe\xe2G\x12#\xac\xc2\x8e\x98\x19$cHe\xf7T:\xed"
        "\xfbK"
    ),
}


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    wrapping_algorithm = attr.ib()
    encryption_key_type = attr.ib()
    key_bytes = attr.ib(default=None)


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Master Key Provider for testing which always returns keys consisting of the raw bytes which were configuring
    during instantiation."""

    provider_id = "ProviderName"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=self.config.wrapping_algorithm,
            wrapping_key=self.config.key_bytes,
            wrapping_key_type=self.config.encryption_key_type,
        )


def test_decrypt_v2_good_commitment():
    """Tests forwards compatibility with message serialization format v2."""
    client = aws_encryption_sdk.EncryptionSDKClient()
    provider = StaticRawMasterKeyProvider(
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        encryption_key_type=EncryptionKeyType.SYMMETRIC,
        key_bytes=b"\00" * 32,
    )
    provider.add_master_key("KeyId")
    ciphertext = VALUES["ciphertext_v2_good_commitment"]
    plaintext, _ = client.decrypt(source=ciphertext, key_provider=provider)
    assert plaintext == b"GoodCommitment"


def test_decrypt_v2_bad_commitment():
    """Tests that we fail as expected when receiving a message with incorrect commitment value."""
    client = aws_encryption_sdk.EncryptionSDKClient()
    provider = StaticRawMasterKeyProvider(
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        encryption_key_type=EncryptionKeyType.SYMMETRIC,
        key_bytes=b"\00" * 32,
    )
    provider.add_master_key("KeyId")

    ciphertext = VALUES["ciphertext_v2_bad_commitment"]

    with pytest.raises(MasterKeyProviderError) as excinfo:
        client.decrypt(source=ciphertext, key_provider=provider)
    excinfo.match("Key commitment validation failed")


def test_encrypt_with_committing_algorithm_policy_forbids_encrypt():
    """Tests that a client configured with CommitmentPolicy FORBID_ENCRYPT_ALLOW_DECRYPT cannot encrypt using an
    algorithm that provides commitment."""
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

    algorithm = aws_encryption_sdk.Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    provider = fake_kms_key_provider(algorithm.kdf_input_len)
    plaintext = b"Yellow Submarine"

    with pytest.raises(ActionNotAllowedError) as excinfo:
        client.encrypt(
            source=plaintext,
            key_provider=provider,
            algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        )

    excinfo.match("Configuration conflict. Cannot encrypt due to .* requiring only non-committed messages")


@pytest.mark.parametrize(
    "policy",
    (
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    ),
)
def test_encrypt_with_committing_algorithm_allow_decrypt(policy):
    """Tests that a client configured with a CommitmentPolicy which allows decryption of committed ciphertexts can
    decrypt a ciphertext encrypted by an algorithm that does provides commitment."""
    encrypting_client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    algorithm = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    provider = fake_kms_key_provider(algorithm.kdf_input_len)
    plaintext = b"Yellow Submarine"

    ciphertext, _ = encrypting_client.encrypt(
        source=plaintext,
        key_provider=provider,
        algorithm=algorithm,
    )

    decrypting_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=policy)

    decrypted, _ = decrypting_client.decrypt(source=ciphertext, key_provider=provider)
    assert decrypted == plaintext


@pytest.mark.parametrize(
    "policy", (CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
)
def test_encrypt_with_uncommitting_algorithm_policy_requires_encrypt(policy):
    """Tests that a client configured with CommitmentPolicy which requires commitment on encrypt cannot encrypt using an
    algorithm that does not provide commitment."""
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=policy)

    algorithm = Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    provider = fake_kms_key_provider(algorithm.kdf_input_len)
    plaintext = b"Yellow Submarine"

    with pytest.raises(ActionNotAllowedError) as excinfo:
        client.encrypt(source=plaintext, key_provider=provider, algorithm=algorithm)

    excinfo.match("Configuration conflict. Cannot encrypt due to .* requiring only committed messages")


@pytest.mark.parametrize(
    "policy", (CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
)
def test_encrypt_with_committing_algorithm_policy_requires_encrypt(policy):
    """Tests that a client configured with CommitmentPolicy which requires commitment on encrypt can encrypt using an
    algorithm that provides commitment."""
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=policy)

    algorithm = Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    provider = fake_kms_key_provider(algorithm.kdf_input_len)
    plaintext = b"Yellow Submarine"

    ciphertext, _ = client.encrypt(source=plaintext, key_provider=provider, algorithm=algorithm)

    decrypting_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=policy)

    decrypted, _ = decrypting_client.decrypt(source=ciphertext, key_provider=provider)
    assert decrypted == plaintext


@pytest.mark.parametrize(
    "policy", (CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
)
def test_encrypt_with_uncommitting_algorithm_allow_decrypt(policy):
    """Tests that a client configured with CommitmentPolicy which allows decryption uncommitted ciphertexts can decrypt
    a ciphertext encrypted by an algorithm that does not provide commitment."""
    encrypting_client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    algorithm = Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    provider = fake_kms_key_provider(algorithm.kdf_input_len)
    plaintext = b"Yellow Submarine"

    ciphertext, _ = encrypting_client.encrypt(
        source=plaintext,
        key_provider=provider,
        algorithm=algorithm,
    )

    decrypting_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=policy)

    decrypted, _ = decrypting_client.decrypt(source=ciphertext, key_provider=provider)
    assert decrypted == plaintext


def test_encrypt_with_uncommitting_algorithm_require_decrypt():
    """Tests that a client configured with CommitmentPolicy REQUIRE_ENCRYPT_REQUIRE_DECRYPT cannot decrypt a ciphertext
    encrypted by an algorithm that does not provide commitment."""
    encrypting_client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    algorithm = Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    key_provider = fake_kms_key_provider(algorithm.kdf_input_len)
    plaintext = b"Yellow Submarine"

    ciphertext, _ = encrypting_client.encrypt(source=plaintext, key_provider=key_provider, algorithm=algorithm)

    decrypting_client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    with pytest.raises(ActionNotAllowedError) as excinfo:
        decrypting_client.decrypt(source=ciphertext, key_provider=key_provider)
    excinfo.match("Configuration conflict. Cannot decrypt due to .* requiring only committed messages")
