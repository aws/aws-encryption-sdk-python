# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional test suite for aws_encryption_sdk.kms_thick_client"""
from __future__ import division

import io
import itertools
import logging

import attr
import botocore.client
import cryptography.exceptions
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from mock import MagicMock
from wrapt import ObjectProxy

import aws_encryption_sdk
from aws_encryption_sdk import KMSMasterKeyProvider
from aws_encryption_sdk.caches import build_decryption_materials_cache_key, build_encryption_materials_cache_key
from aws_encryption_sdk.exceptions import CustomMaximumValueExceeded
from aws_encryption_sdk.identifiers import Algorithm, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.defaults import LINE_LENGTH
from aws_encryption_sdk.internal.formatting.encryption_context import serialize_encryption_context
from aws_encryption_sdk.key_providers.base import MasterKeyProvider, MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.keyrings.raw import RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest

from ..unit.unit_test_utils import (
    ephemeral_raw_aes_keyring,
    ephemeral_raw_aes_master_key,
    ephemeral_raw_rsa_keyring,
    raw_rsa_mkps_from_keyring,
)

pytestmark = [pytest.mark.functional, pytest.mark.local]

VALUES = {
    "frame_lengths": (  # Assuming 1280 byte plaintext:
        0,  # Non-framed
        128,  # Many frames
        1280,  # One exactly full frame, empty final frame
        2048,  # One partial, final, frame
    ),
    "data_keys": {
        16: {
            "plaintext": b"v\x84\xc1\x13\x9c\xa8\xaa\xaa\xf3\x07*k8\xa2\xb5]",
            "encrypted": (
                b"\x01\x01\x01\x00x\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6"
                b"\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00n0l\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0_0]\x02\x01\x000X\x06"
                b"\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xe9\xd2\x15M8\xfa\xf5"
                b"Z\xc5\xd5l\xf8\x02\x01\x10\x80+\xf7\x1f]\xfc\xbc\xb7\xff\xed|\x81\x99)<x\x18, \x9f\x11\xac\xaa\xd3?q"
                b"$\xf6\xd9\x85\xfcp\xb6z\x88\x8d\xa4\x9e\xe4U\xe6\xe7}W\xcf"
            ),
        },
        24: {
            "plaintext": b":\xa7!\xe5\xe8j(u\xb8'\xb2\x1eX`k\x11Ak\x06\x80\xc8\x8c\x83D",
            "encrypted": (
                b"\x01\x01\x01\x00x\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6"
                b"\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00v0t\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0g0e\x02\x01\x000`\x06"
                b"\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0cQLG\x10\xe9\x99\x06"
                b"\x1e*\xc3\xc8K\x02\x01\x10\x803\xfa\x83\xad\xe8\\@\x06F\xcd\x01/\x82w\xe8,C\xb7\xdev$\xec66\xa7h\x1d"
                b"c\xb5\xd3\xda\x18\xff\x96$\xf5\xaf\x7f\xc6c\x01\xeb\x85R\xc0\xa7\xcd\xbf\xaf\xb3|\xfe"
            ),
        },
        32: {
            "plaintext": (
                b"uW\x05\x10\x0fg\x81\xbc\xec\x97\xb3o\xe2\xc7\xd0\r,\x85N\x9f\x8c\x9b\x92&\xfe\xa4\xae\xd5\xf5\x9b"
                b"\xc7e"
            ),
            "encrypted": (
                b"\x01\x01\x01\x00x\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6"
                b"\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00~0|\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01\x000h\x06"
                b"\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xbc\xaf\x0cf^\xf8\xbb"
                b"\xa5\x80-B\xc2\x02\x01\x10\x80;mT\xc2V\x8eN\xa5b\xf2@7_\xa6n\x94\xe6i\xdegM\xe8E\xa6\xb9-H\xf0\x8cBp"
                b"\xc7R\xbb\x04\x8f\xf1+\xc5\x94u-\xf9[\xb9\xf0N*\x9f=:\xda\x9b\xdd\xdd\x08\xe4\x1b\x00("
            ),
        },
    },
    "plaintext_128": (
        b"\xa3\xf6\xbc\x89\x95\x15(\xc8}\\\x8d=zu^{JA\xc1\xe9\xf0&m\xe6TD\x03"
        b"\x165F\x85\xae\x96\xd9~ \xa6\x13\x88\xf8\xdb\xc9\x0c\xd8\xd8\xd4\xe0"
        b"\x02\xe9\xdb+\xd4l\xeaq\xf6\xba.cg\xda\xe4V\xd9\x9a\x96\xe8\xf4:\xf5"
        b"\xfd\xd7\xa6\xfa\xd1\x85\xa7o\xf5\x94\xbcE\x14L\xa1\x87\xd9T\xa6\x95"
        b"eZVv\xfe[\xeeJ$a<9\x1f\x97\xe1\xd6\x9dQc\x8b7n\x0f\x1e\xbd\xf5\xba"
        b"\x0e\xae|%\xd8L]\xa2\xa2\x08\x1f"
    ),
    "encryption_context": {"key_a": "value_a", "key_b": "value_b", "key_c": "value_c"},
    "arn": b"arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333",
    "provided": {
        "key": b"\x90\x86Z\x95\x96l'\xa7\x00yA\x9a\x1a\"\xa9\x8e",
        "ciphertext": (
            b"\x01\x80\x00\x14\xe7\xc7\x81\xcfo\x04\xb9\xd3\xbe\xa5\xe5\t,\xb8\x8f\xeb\x00"
            b"\n\x00\x01\x00\x02aa\x00\x02aa\x00\x01\x00\x07aws-kms\x00Karn:aws:kms:us-wes"
            b"t-2:249645522726:key/d1720f4e-953b-44bb-b9dd-fc8b9d0baa5f\x00\xbc\n \xf5\x9b"
            b"\x99\x8cX\xa8U\xa9\xbbF\x00\xcf\xd2\xaf+\xd90\xfe\xf3\r\x0e\xdb\x1c\xaf\xf9"
            b"\xfa\x7f\x17\xe8\xb2\xda\xc2\x12\x97\x01\x01\x01\x01\x00x\xf5\x9b\x99\x8cX"
            b"\xa8U\xa9\xbbF\x00\xcf\xd2\xaf+\xd90\xfe\xf3\r\x0e\xdb\x1c\xaf\xf9\xfa\x7f"
            b"\x17\xe8\xb2\xda\xc2\x00\x00\x00n0l\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0_0]"
            b"\x02\x01\x000X\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04"
            b"\x01.0\x11\x04\x0c\x88^o\xd5|\xf2rj`\x06\x80(\x02\x01\x10\x80+\x04\x1cb0\xaf\xff"
            b"V^\x01\x94\xc2\xb1\x7fQ\x02\xde\xd6@\x875\xe9%f\x1c\xb0IS\xc7\xacx\x14\xb2\xea"
            b"\xf6\x80\xfc2\xeb\x99x\xc9\x88Q\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x19m!"
            b"\x15FG\xeeG\x8b\xb2\x03w\xe6\xa6\xfbm}My\x07\xef\xac*\x82\x98\xb6\x84FF\x94%\x8f"
            b"\x97\xed3 \x12\x06\x16\xcf\x00\x00\x00\x00\x00\x00\x00\x1a\x82\xe2$\xb5\xbd\x8c"
            b"\xb4\xcf\xdeF\xc5=$\xea\xdeJ\xe6{\xb7&\x83p9|d\xf8,\xa0\xa3\xa0 \xb3d>\x9f \x05t"
            b"\xa9\x7f\x9f\xed"
        ),
        "plaintext": b"Hello, I'm Java KMS client",
    },
    "raw": {
        b"sym1": {EncryptionKeyType.SYMMETRIC: b"12345678901234567890123456789012"},
        b"asym1": {
            EncryptionKeyType.PRIVATE: (
                b"-----BEGIN RSA PRIVATE KEY-----\n"
                b"MIIEowIBAAKCAQEAo8uCyhiO4JUGZV+rtNq5DBA9Lm4xkw5kTA3v6EPybs8bVXL2\n"
                b"ZE6jkbo+xT4Jg/bKzUpnp1fE+T1ruGPtsPdoEmhY/P64LDNIs3sRq5U4QV9IETU1\n"
                b"vIcbNNkgGhRjV8J87YNY0tV0H7tuWuZRpqnS+gjV6V9lUMkbvjMCc5IBqQc3heut\n"
                b"/+fH4JwpGlGxOVXI8QAapnSy1XpCr3+PT29kydVJnIMuAoFrurojRpOQbOuVvhtA\n"
                b"gARhst1Ji4nfROGYkj6eZhvkz2Bkud4/+3lGvVU5LO1vD8oY7WoGtpin3h50VcWe\n"
                b"aBT4kejx4s9/G9C4R24lTH09J9HO2UUsuCqZYQIDAQABAoIBAQCfC90bCk+qaWqF\n"
                b"gymC+qOWwCn4bM28gswHQb1D5r6AtKBRD8mKywVvWs7azguFVV3Fi8sspkBA2FBC\n"
                b"At5p6ULoJOTL/TauzLl6djVJTCMM701WUDm2r+ZOIctXJ5bzP4n5Q4I7b0NMEL7u\n"
                b"ixib4elYGr5D1vrVQAKtZHCr8gmkqyx8Mz7wkJepzBP9EeVzETCHsmiQDd5WYlO1\n"
                b"C2IQYgw6MJzgM4entJ0V/GPytkodblGY95ORVK7ZhyNtda+r5BZ6/jeMW+hA3VoK\n"
                b"tHSWjHt06ueVCCieZIATmYzBNt+zEz5UA2l7ksg3eWfVORJQS7a6Ef4VvbJLM9Ca\n"
                b"m1kdsjelAoGBANKgvRf39i3bSuvm5VoyJuqinSb/23IH3Zo7XOZ5G164vh49E9Cq\n"
                b"dOXXVxox74ppj/kbGUoOk+AvaB48zzfzNvac0a7lRHExykPH2kVrI/NwH/1OcT/x\n"
                b"2e2DnFYocXcb4gbdZQ+m6X3zkxOYcONRzPVW1uMrFTWHcJveMUm4PGx7AoGBAMcU\n"
                b"IRvrT6ye5se0s27gHnPweV+3xjsNtXZcK82N7duXyHmNjxrwOAv0SOhUmTkRXArM\n"
                b"6aN5D8vyZBSWma2TgUKwpQYFTI+4Sp7sdkkyojGAEixJ+c5TZJNxZFrUe0FwAoic\n"
                b"c2kb7ntaiEj5G+qHvykJJro5hy6uLnjiMVbAiJDTAoGAKb67241EmHAXGEwp9sdr\n"
                b"2SMjnIAnQSF39UKAthkYqJxa6elXDQtLoeYdGE7/V+J2K3wIdhoPiuY6b4vD0iX9\n"
                b"JcGM+WntN7YTjX2FsC588JmvbWfnoDHR7HYiPR1E58N597xXdFOzgUgORVr4PMWQ\n"
                b"pqtwaZO3X2WZlvrhr+e46hMCgYBfdIdrm6jYXFjL6RkgUNZJQUTxYGzsY+ZemlNm\n"
                b"fGdQo7a8kePMRuKY2MkcnXPaqTg49YgRmjq4z8CtHokRcWjJUWnPOTs8rmEZUshk\n"
                b"0KJ0mbQdCFt/Uv0mtXgpFTkEZ3DPkDTGcV4oR4CRfOCl0/EU/A5VvL/U4i/mRo7h\n"
                b"ye+xgQKBgD58b+9z+PR5LAJm1tZHIwb4tnyczP28PzwknxFd2qylR4ZNgvAUqGtU\n"
                b"xvpUDpzMioz6zUH9YV43YNtt+5Xnzkqj+u9Mr27/H2v9XPwORGfwQ5XPwRJz/2oC\n"
                b"EnPmP1SZoY9lXKUpQXHXSpDZ2rE2Klt3RHMUMHt8Zpy36E8Vwx8o\n"
                b"-----END RSA PRIVATE KEY-----\n"
            ),
            EncryptionKeyType.PUBLIC: (
                b"-----BEGIN PUBLIC KEY-----\n"
                b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8uCyhiO4JUGZV+rtNq5\n"
                b"DBA9Lm4xkw5kTA3v6EPybs8bVXL2ZE6jkbo+xT4Jg/bKzUpnp1fE+T1ruGPtsPdo\n"
                b"EmhY/P64LDNIs3sRq5U4QV9IETU1vIcbNNkgGhRjV8J87YNY0tV0H7tuWuZRpqnS\n"
                b"+gjV6V9lUMkbvjMCc5IBqQc3heut/+fH4JwpGlGxOVXI8QAapnSy1XpCr3+PT29k\n"
                b"ydVJnIMuAoFrurojRpOQbOuVvhtAgARhst1Ji4nfROGYkj6eZhvkz2Bkud4/+3lG\n"
                b"vVU5LO1vD8oY7WoGtpin3h50VcWeaBT4kejx4s9/G9C4R24lTH09J9HO2UUsuCqZ\n"
                b"YQIDAQAB\n"
                b"-----END PUBLIC KEY-----\n"
            ),
        },
    },
}


###########
# Helpers #
###########


@attr.s(hash=False)
class FakeRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    wrapping_algorithm = attr.ib()
    encryption_key_type = attr.ib()


class FakeRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "raw"
    _config_class = FakeRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        wrapping_key = VALUES["raw"][key_id][self.config.encryption_key_type]
        if key_id == b"sym1":
            wrapping_key = wrapping_key[: self.config.wrapping_algorithm.algorithm.data_key_len]
        return WrappingKey(
            wrapping_algorithm=self.config.wrapping_algorithm,
            wrapping_key=wrapping_key,
            wrapping_key_type=self.config.encryption_key_type,
        )


def _mgf1_sha256_supported():
    wk = serialization.load_pem_private_key(
        data=VALUES["raw"][b"asym1"][EncryptionKeyType.PRIVATE], password=None, backend=default_backend()
    )
    try:
        wk.public_key().encrypt(
            plaintext=b"aosdjfoiajfoiaj;foijae;rogijaerg",
            padding=padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except cryptography.exceptions.UnsupportedAlgorithm:
        return False
    return True


def fake_kms_client(keysize=32):
    mock_kms_client = MagicMock(__class__=botocore.client.BaseClient)
    mock_kms_client.generate_data_key.return_value = {
        "Plaintext": VALUES["data_keys"][keysize]["plaintext"],
        "CiphertextBlob": VALUES["data_keys"][keysize]["encrypted"],
        "KeyId": VALUES["arn"],
    }
    mock_kms_client.encrypt.return_value = {
        "CiphertextBlob": VALUES["data_keys"][keysize]["encrypted"],
        "KeyId": VALUES["arn"],
    }
    mock_kms_client.decrypt.return_value = {
        "Plaintext": VALUES["data_keys"][keysize]["plaintext"],
        "KeyId": VALUES["arn"],
    }
    return mock_kms_client


def fake_kms_key_provider(keysize=32):
    mock_kms_key_provider = KMSMasterKeyProvider()
    mock_kms_key_provider._regional_clients["us-east-1"] = fake_kms_client(keysize)
    mock_kms_key_provider.add_master_key(VALUES["arn"])
    return mock_kms_key_provider


def build_fake_raw_key_provider(wrapping_algorithm, encryption_key_type):
    key_info = {
        EncryptionKeyType.SYMMETRIC: b"sym1",
        EncryptionKeyType.PRIVATE: b"asym1",
        EncryptionKeyType.PUBLIC: b"asym1",
    }
    raw_key_provider = FakeRawMasterKeyProvider(
        wrapping_algorithm=wrapping_algorithm, encryption_key_type=encryption_key_type
    )
    raw_key_provider.add_master_key(key_info[encryption_key_type])
    return raw_key_provider


#########
# Tests #
#########


def test_no_infinite_encryption_cycle_on_empty_source():
    """This catches a race condition where when calling encrypt with
        an empty byte string, encrypt would enter an infinite loop.
        If this test does not hang, the race condition is not present.
    """
    aws_encryption_sdk.encrypt(source=b"", key_provider=fake_kms_key_provider())


def test_encrypt_load_header():
    """Test that StreamEncryptor can extract header without reading plaintext."""
    # Using a non-signed algorithm to simplify header size calculation
    algorithm = aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
    key_provider = fake_kms_key_provider(algorithm.kdf_input_len)
    header_length = len(serialize_encryption_context(VALUES["encryption_context"]))
    header_length += 34
    header_length += algorithm.iv_len
    header_length += algorithm.auth_len
    header_length += 6 + 7 + len(VALUES["arn"]) + len(VALUES["data_keys"][algorithm.kdf_input_len]["encrypted"])
    with aws_encryption_sdk.stream(
        mode="e",
        source=VALUES["plaintext_128"],
        key_provider=key_provider,
        encryption_context=VALUES["encryption_context"],
        algorithm=algorithm,
        frame_length=1024,
    ) as encryptor:
        encryptor_header = encryptor.header
    # Ensure that only the header has been written into the output buffer
    assert len(encryptor.output_buffer) == header_length
    assert encryptor_header.encryption_context == VALUES["encryption_context"]


def test_encrypt_decrypt_header_only():
    """Test that StreamDecryptor can extract header without reading ciphertext."""
    ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
        source=VALUES["plaintext_128"],
        key_provider=fake_kms_key_provider(),
        encryption_context=VALUES["encryption_context"],
    )
    with aws_encryption_sdk.stream(mode="d", source=ciphertext, key_provider=fake_kms_key_provider()) as decryptor:
        decryptor_header = decryptor.header
    assert decryptor.output_buffer == b""
    assert all(
        pair in decryptor_header.encryption_context.items() for pair in encryptor_header.encryption_context.items()
    )


@pytest.mark.parametrize(
    "frame_length, algorithm, encryption_context",
    [
        [frame_length, algorithm_suite, encryption_context]
        for frame_length in VALUES["frame_lengths"]
        for algorithm_suite in Algorithm
        for encryption_context in [{}, VALUES["encryption_context"]]
    ],
)
def test_encrypt_ciphertext_message(frame_length, algorithm, encryption_context):
    with aws_encryption_sdk.stream(
        mode="e",
        source=VALUES["plaintext_128"] * 10,
        key_provider=fake_kms_key_provider(algorithm.kdf_input_len),
        encryption_context=encryption_context,
        algorithm=algorithm,
        frame_length=frame_length,
    ) as encryptor:
        results_length = encryptor.ciphertext_length()
        ciphertext = encryptor.read()

    assert len(ciphertext) == results_length


def _raw_aes(include_mkp=True):
    for symmetric_algorithm in (
        WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
        WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
        WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    ):
        keyring = ephemeral_raw_aes_keyring(symmetric_algorithm)
        yield pytest.param(
            "keyring", keyring, "keyring", keyring, id="raw AES keyring -- {}".format(symmetric_algorithm.name)
        )

        if not include_mkp:
            continue

        yield pytest.param(
            "key_provider",
            build_fake_raw_key_provider(symmetric_algorithm, EncryptionKeyType.SYMMETRIC),
            "key_provider",
            build_fake_raw_key_provider(symmetric_algorithm, EncryptionKeyType.SYMMETRIC),
            id="raw AES master key provider -- {}".format(symmetric_algorithm.name),
        )

        mkp = ephemeral_raw_aes_master_key(wrapping_algorithm=symmetric_algorithm, key=keyring._wrapping_key)
        yield pytest.param(
            "key_provider",
            mkp,
            "keyring",
            keyring,
            id="raw AES -- encrypt with master key provider and decrypt with keyring -- {}".format(symmetric_algorithm),
        )
        yield pytest.param(
            "keyring",
            keyring,
            "key_provider",
            mkp,
            id="raw AES -- encrypt with keyring and decrypt with master key provider -- {}".format(symmetric_algorithm),
        )


def _raw_rsa(include_pre_sha2=True, include_sha2=True, include_mkp=True):
    wrapping_algorithms = []
    if include_pre_sha2:
        wrapping_algorithms.extend([WrappingAlgorithm.RSA_PKCS1, WrappingAlgorithm.RSA_OAEP_SHA1_MGF1])
    if include_sha2:
        wrapping_algorithms.extend(
            [
                WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
                WrappingAlgorithm.RSA_OAEP_SHA384_MGF1,
                WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
            ]
        )
    for wrapping_algorithm in wrapping_algorithms:
        private_keyring = ephemeral_raw_rsa_keyring(wrapping_algorithm=wrapping_algorithm)
        public_keyring = RawRSAKeyring(
            key_namespace=private_keyring.key_namespace,
            key_name=private_keyring.key_name,
            wrapping_algorithm=wrapping_algorithm,
            public_wrapping_key=private_keyring._private_wrapping_key.public_key(),
        )
        yield pytest.param(
            "keyring",
            private_keyring,
            "keyring",
            private_keyring,
            id="raw RSA keyring -- private encrypt, private decrypt -- {}".format(wrapping_algorithm.name),
        )
        yield pytest.param(
            "keyring",
            public_keyring,
            "keyring",
            private_keyring,
            id="raw RSA keyring -- public encrypt, private decrypt -- {}".format(wrapping_algorithm.name),
        )

        if not include_mkp:
            continue

        private_mkp, public_mkp = raw_rsa_mkps_from_keyring(private_keyring)

        yield pytest.param(
            "key_provider",
            build_fake_raw_key_provider(wrapping_algorithm, EncryptionKeyType.PRIVATE),
            "key_provider",
            build_fake_raw_key_provider(wrapping_algorithm, EncryptionKeyType.PRIVATE),
            id="raw RSA master key provider -- private encrypt, private decrypt -- {}".format(wrapping_algorithm.name),
        )
        yield pytest.param(
            "key_provider",
            build_fake_raw_key_provider(wrapping_algorithm, EncryptionKeyType.PUBLIC),
            "key_provider",
            build_fake_raw_key_provider(wrapping_algorithm, EncryptionKeyType.PRIVATE),
            id="raw RSA master key provider -- public encrypt, private decrypt -- {}".format(wrapping_algorithm.name),
        )

        yield pytest.param(
            "key_provider",
            private_mkp,
            "keyring",
            private_keyring,
            id="raw RSA keyring -- private master key provider encrypt and private keyring decrypt -- {}".format(
                wrapping_algorithm
            ),
        )
        yield pytest.param(
            "key_provider",
            public_mkp,
            "keyring",
            private_keyring,
            id="raw RSA keyring -- public master key provider encrypt and private keyring decrypt -- {}".format(
                wrapping_algorithm
            ),
        )
        yield pytest.param(
            "keyring",
            private_keyring,
            "key_provider",
            private_mkp,
            id="raw RSA keyring -- private keyring encrypt and private master key provider decrypt -- {}".format(
                wrapping_algorithm
            ),
        )
        yield pytest.param(
            "keyring",
            public_keyring,
            "key_provider",
            private_mkp,
            id="raw RSA keyring -- public keyring encrypt and private master key provider decrypt -- {}".format(
                wrapping_algorithm
            ),
        )


def assert_key_not_logged(provider, log_capture):
    if isinstance(provider, MasterKeyProvider):
        for member in provider._members:
            assert repr(member.config.wrapping_key._wrapping_key)[2:-1] not in log_capture


def run_raw_provider_check(
    log_capturer, encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider
):
    log_capturer.set_level(logging.DEBUG)

    encrypt_kwargs = {encrypt_param_name: encrypting_provider}
    decrypt_kwargs = {decrypt_param_name: decrypting_provider}

    encrypt_result = aws_encryption_sdk.encrypt(
        source=VALUES["plaintext_128"],
        encryption_context=VALUES["encryption_context"],
        frame_length=0,
        **encrypt_kwargs
    )
    decrypt_result = aws_encryption_sdk.decrypt(source=encrypt_result.result, **decrypt_kwargs)

    if isinstance(encrypting_provider, Keyring):
        trace_entries = (
            entry
            for entry in encrypt_result.keyring_trace
            if (
                entry.wrapping_key.provider_id == encrypting_provider.key_namespace
                and entry.wrapping_key.key_info == encrypting_provider.key_name
            )
        )
        assert trace_entries

    assert decrypt_result.result == VALUES["plaintext_128"]
    assert_key_not_logged(encrypting_provider, log_capturer.text)

    if isinstance(decrypting_provider, Keyring):
        trace_entries = (
            entry
            for entry in decrypt_result.keyring_trace
            if (
                entry.wrapping_key.provider_id == decrypting_provider.key_namespace
                and entry.wrapping_key.key_info == decrypting_provider.key_name
            )
        )
        assert trace_entries


@pytest.mark.parametrize(
    "encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider",
    itertools.chain.from_iterable((_raw_aes(), _raw_rsa(include_sha2=False))),
)
def test_encryption_cycle_raw_mkp(
    caplog, encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider
):
    run_raw_provider_check(caplog, encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider)


@pytest.mark.skipif(
    not _mgf1_sha256_supported(), reason="MGF1-SHA2 not supported by this backend: OpenSSL required v1.0.2+"
)
@pytest.mark.parametrize(
    "encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider", _raw_rsa(include_pre_sha2=False)
)
def test_encryption_cycle_raw_mkp_openssl_102_plus(
    caplog, encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider
):
    run_raw_provider_check(caplog, encrypt_param_name, encrypting_provider, decrypt_param_name, decrypting_provider)


@pytest.mark.parametrize("frame_length", VALUES["frame_lengths"])
@pytest.mark.parametrize("algorithm", Algorithm)
@pytest.mark.parametrize("encryption_context", [{}, VALUES["encryption_context"]])
def test_encryption_cycle_oneshot_kms(frame_length, algorithm, encryption_context):
    key_provider = fake_kms_key_provider(algorithm.kdf_input_len)

    ciphertext, _ = aws_encryption_sdk.encrypt(
        source=VALUES["plaintext_128"] * 10,
        key_provider=key_provider,
        frame_length=frame_length,
        algorithm=algorithm,
        encryption_context=encryption_context,
    )

    plaintext, _ = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=key_provider)

    assert plaintext == VALUES["plaintext_128"] * 10


@pytest.mark.parametrize("frame_length", VALUES["frame_lengths"])
@pytest.mark.parametrize("algorithm", Algorithm)
@pytest.mark.parametrize("encryption_context", [{}, VALUES["encryption_context"]])
def test_encryption_cycle_stream_kms(frame_length, algorithm, encryption_context):
    key_provider = fake_kms_key_provider(algorithm.kdf_input_len)

    ciphertext = bytearray()
    with aws_encryption_sdk.stream(
        mode="e",
        source=VALUES["plaintext_128"] * 10,
        key_provider=key_provider,
        frame_length=frame_length,
        algorithm=algorithm,
        encryption_context=encryption_context,
    ) as encryptor:
        for chunk in encryptor:
            ciphertext.extend(chunk)
    ciphertext = bytes(ciphertext)

    plaintext = bytearray()
    with aws_encryption_sdk.stream(mode="d", source=io.BytesIO(ciphertext), key_provider=key_provider) as decryptor:
        for chunk in decryptor:
            plaintext.extend(chunk)
    plaintext = bytes(plaintext)

    assert ciphertext != plaintext
    assert plaintext == VALUES["plaintext_128"] * 10
    assert encryptor.header.encryption_context == decryptor.header.encryption_context


def test_decrypt_legacy_provided_message():
    """Tests backwards compatiblity against some legacy provided ciphertext."""
    region = "us-west-2"
    key_info = "arn:aws:kms:us-west-2:249645522726:key/d1720f4e-953b-44bb-b9dd-fc8b9d0baa5f"
    mock_kms_client = fake_kms_client()
    mock_kms_client.decrypt.return_value = {"Plaintext": VALUES["provided"]["key"]}
    mock_kms_key_provider = fake_kms_key_provider()
    mock_kms_key_provider._regional_clients[region] = mock_kms_client
    mock_kms_key_provider.add_master_key(key_info)
    plaintext, _ = aws_encryption_sdk.decrypt(
        source=VALUES["provided"]["ciphertext"], key_provider=mock_kms_key_provider
    )
    assert plaintext == VALUES["provided"]["plaintext"]


def test_encryption_cycle_with_caching():
    algorithm = Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    frame_length = 1024
    key_provider = fake_kms_key_provider(algorithm.kdf_input_len)
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=10)
    ccmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=key_provider, cache=cache, max_age=3600.0, max_messages_encrypted=5
    )
    encrypt_kwargs = dict(
        source=VALUES["plaintext_128"],
        materials_manager=ccmm,
        encryption_context=VALUES["encryption_context"],
        frame_length=frame_length,
        algorithm=algorithm,
    )
    encrypt_cache_key = build_encryption_materials_cache_key(
        partition=ccmm.partition_name,
        request=EncryptionMaterialsRequest(
            encryption_context=VALUES["encryption_context"],
            frame_length=frame_length,
            algorithm=algorithm,
            plaintext_length=len(VALUES["plaintext_128"]),
        ),
    )
    ciphertext, header = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    decrypt_cache_key = build_decryption_materials_cache_key(
        partition=ccmm.partition_name,
        request=DecryptionMaterialsRequest(
            algorithm=algorithm,
            encrypted_data_keys=header.encrypted_data_keys,
            encryption_context=header.encryption_context,
        ),
    )

    assert len(cache._cache) == 1
    assert cache._cache[encrypt_cache_key].messages_encrypted == 1
    assert cache._cache[encrypt_cache_key].bytes_encrypted == 128

    _, _ = aws_encryption_sdk.decrypt(source=ciphertext, materials_manager=ccmm)

    assert len(cache._cache) == 2
    assert decrypt_cache_key in cache._cache

    _, _ = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    _, _ = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    _, _ = aws_encryption_sdk.encrypt(**encrypt_kwargs)

    assert len(cache._cache) == 2
    assert cache._cache[encrypt_cache_key].messages_encrypted == 4
    assert cache._cache[encrypt_cache_key].bytes_encrypted == 512

    _, _ = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    _, _ = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    _, _ = aws_encryption_sdk.encrypt(**encrypt_kwargs)

    assert len(cache._cache) == 2
    assert cache._cache[encrypt_cache_key].messages_encrypted == 2
    assert cache._cache[encrypt_cache_key].bytes_encrypted == 256


def test_encrypt_source_length_enforcement():
    key_provider = fake_kms_key_provider()
    cmm = aws_encryption_sdk.DefaultCryptoMaterialsManager(key_provider)
    plaintext = io.BytesIO(VALUES["plaintext_128"])
    with pytest.raises(CustomMaximumValueExceeded) as excinfo:
        aws_encryption_sdk.encrypt(
            source=plaintext, materials_manager=cmm, source_length=int(len(VALUES["plaintext_128"]) / 2)
        )

    excinfo.match(r"Bytes encrypted has exceeded stated source length estimate:*")
    assert repr(plaintext) not in excinfo.exconly()


def test_encrypt_source_length_enforcement_legacy_support():
    # To maintain legacy compatibility, source length is only enforced
    # if a crypto materials manager is provided; not if a master key
    # provider is provided.
    key_provider = fake_kms_key_provider()
    aws_encryption_sdk.encrypt(
        source=VALUES["plaintext_128"], key_provider=key_provider, source_length=int(len(VALUES["plaintext_128"]) / 2)
    )


class NoSeekBytesIO(io.BytesIO):
    """``io.BytesIO`` that blocks ``seek()`` and ``tell()``."""

    def seekable(self):
        return False

    def seek(self, offset, whence=0):
        raise NotImplementedError("seek is blocked")

    def tell(self):
        raise NotImplementedError("tell is blocked")


def test_stream_encryptor_no_seek_input():
    """Test that StreamEncryptor can handle an input stream that is not seekable."""
    key_provider = fake_kms_key_provider()
    plaintext = NoSeekBytesIO(VALUES["plaintext_128"])
    ciphertext = io.BytesIO()
    with aws_encryption_sdk.StreamEncryptor(
        source=plaintext, key_provider=key_provider, encryption_context=VALUES["encryption_context"]
    ) as encryptor:
        for chunk in encryptor:
            ciphertext.write(chunk)
    decrypted, _header = aws_encryption_sdk.decrypt(source=ciphertext.getvalue(), key_provider=key_provider)
    assert decrypted == VALUES["plaintext_128"]


def test_stream_decryptor_no_seek_input():
    """Test that StreamDecryptor can handle an input stream that is not seekable."""
    key_provider = fake_kms_key_provider()
    ciphertext, _header = aws_encryption_sdk.encrypt(
        source=VALUES["plaintext_128"], key_provider=key_provider, encryption_context=VALUES["encryption_context"]
    )
    ciphertext_no_seek = NoSeekBytesIO(ciphertext)
    decrypted = io.BytesIO()
    with aws_encryption_sdk.StreamDecryptor(source=ciphertext_no_seek, key_provider=key_provider) as decryptor:
        for chunk in decryptor:
            decrypted.write(chunk)
    assert decrypted.getvalue() == VALUES["plaintext_128"]


def test_encrypt_oneshot_no_seek_input():
    """Test that encrypt can handle an input stream that is not seekable."""
    key_provider = fake_kms_key_provider()
    plaintext = NoSeekBytesIO(VALUES["plaintext_128"])
    ciphertext, _header = aws_encryption_sdk.encrypt(
        source=plaintext, key_provider=key_provider, encryption_context=VALUES["encryption_context"]
    )
    decrypted, _header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=key_provider)
    assert decrypted == VALUES["plaintext_128"]


def test_decrypt_oneshot_no_seek_input():
    """Test that decrypt can handle an input stream that is not seekable."""
    key_provider = fake_kms_key_provider()
    ciphertext, _header = aws_encryption_sdk.encrypt(
        source=VALUES["plaintext_128"], key_provider=key_provider, encryption_context=VALUES["encryption_context"]
    )
    ciphertext_no_seek = NoSeekBytesIO(ciphertext)
    decrypted, _header = aws_encryption_sdk.decrypt(source=ciphertext_no_seek, key_provider=key_provider)
    assert decrypted == VALUES["plaintext_128"]


def test_stream_encryptor_readable():
    """Verify that open StreamEncryptor instances report as readable."""
    key_provider = fake_kms_key_provider()
    plaintext = io.BytesIO(VALUES["plaintext_128"])
    with aws_encryption_sdk.StreamEncryptor(source=plaintext, key_provider=key_provider) as handler:
        assert handler.readable()
        handler.read()
    assert not handler.readable()


def test_stream_decryptor_readable():
    """Verify that open StreamEncryptor instances report as readable."""
    key_provider = fake_kms_key_provider()
    plaintext = io.BytesIO(VALUES["plaintext_128"])
    ciphertext, _header = aws_encryption_sdk.encrypt(source=plaintext, key_provider=key_provider)
    with aws_encryption_sdk.StreamDecryptor(source=ciphertext, key_provider=key_provider) as handler:
        assert handler.readable()
        handler.read()
    assert not handler.readable()


def exact_length_plaintext(length):
    plaintext = b""
    while len(plaintext) < length:
        plaintext += VALUES["plaintext_128"]
    return plaintext[:length]


class SometimesIncompleteReaderIO(io.BytesIO):
    def __init__(self, *args, **kwargs):
        self.__read_counter = 0
        super(SometimesIncompleteReaderIO, self).__init__(*args, **kwargs)

    def read(self, size=-1):
        """Every other read request, return fewer than the requested number of bytes if more than one byte requested."""
        self.__read_counter += 1
        if size > 1 and self.__read_counter % 2 == 0:
            size //= 2
        return super(SometimesIncompleteReaderIO, self).read(size)


@pytest.mark.parametrize(
    "frame_length",
    (
        0,  # 0: unframed
        128,  # 128: framed with exact final frame size match
        256,  # 256: framed with inexact final frame size match
    ),
)
def test_incomplete_read_stream_cycle(frame_length):
    chunk_size = 21  # Will never be an exact match for the frame size
    key_provider = fake_kms_key_provider()

    plaintext = exact_length_plaintext(384)
    ciphertext = b""
    cycle_count = 0
    with aws_encryption_sdk.stream(
        mode="encrypt",
        source=SometimesIncompleteReaderIO(plaintext),
        key_provider=key_provider,
        frame_length=frame_length,
    ) as encryptor:
        while True:
            cycle_count += 1
            chunk = encryptor.read(chunk_size)
            if not chunk:
                break
            ciphertext += chunk
            if cycle_count > len(VALUES["plaintext_128"]):
                raise aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError(
                    "Unexpected error encrypting message: infinite loop detected."
                )

    decrypted = b""
    cycle_count = 0
    with aws_encryption_sdk.stream(
        mode="decrypt", source=SometimesIncompleteReaderIO(ciphertext), key_provider=key_provider
    ) as decryptor:
        while True:
            cycle_count += 1
            chunk = decryptor.read(chunk_size)
            if not chunk:
                break
            decrypted += chunk
            if cycle_count > len(VALUES["plaintext_128"]):
                raise aws_encryption_sdk.exceptions.AWSEncryptionSDKClientError(
                    "Unexpected error encrypting message: infinite loop detected."
                )

    assert ciphertext != decrypted == plaintext


def _prep_plaintext_and_logs(log_catcher, plaintext_length):
    log_catcher.set_level(logging.DEBUG)
    key_provider = fake_kms_key_provider()
    plaintext = exact_length_plaintext(plaintext_length)
    return plaintext, key_provider


def _look_in_logs(log_catcher, plaintext):
    # Verify that no plaintext chunks are in the logs
    logs = log_catcher.text
    # look for all fake KMS data keys
    for args in VALUES["data_keys"].values():
        assert repr(args["plaintext"])[2:-1] not in logs
    # look for every possible 32-byte chunk
    start = 0
    end = 32
    plaintext_length = len(plaintext)
    while end <= plaintext_length:
        chunk_repr = repr(plaintext[start:end])
        repr_body = chunk_repr[2:-1]
        assert repr_body not in logs
        start += 1
        end += 1


def _error_check(capsys_instance):
    # Verify that no error were caught and ignored.
    # The intent is to catch logging errors, but others will be caught as well.
    stderr = capsys_instance.readouterr().err
    assert "Call stack:" not in stderr


@pytest.mark.parametrize("frame_size", (0, LINE_LENGTH // 2, LINE_LENGTH, LINE_LENGTH * 2))
@pytest.mark.parametrize(
    "plaintext_length", (1, LINE_LENGTH // 2, LINE_LENGTH, int(LINE_LENGTH * 1.5), LINE_LENGTH * 2)
)
def test_plaintext_logs_oneshot(caplog, capsys, plaintext_length, frame_size):
    plaintext, key_provider = _prep_plaintext_and_logs(caplog, plaintext_length)

    _ciphertext, _header = aws_encryption_sdk.encrypt(
        source=plaintext, key_provider=key_provider, frame_length=frame_size
    )

    _look_in_logs(caplog, plaintext)
    _error_check(capsys)


@pytest.mark.parametrize("frame_size", (0, LINE_LENGTH // 2, LINE_LENGTH, LINE_LENGTH * 2))
@pytest.mark.parametrize(
    "plaintext_length", (1, LINE_LENGTH // 2, LINE_LENGTH, int(LINE_LENGTH * 1.5), LINE_LENGTH * 2)
)
def test_plaintext_logs_stream(caplog, capsys, plaintext_length, frame_size):
    plaintext, key_provider = _prep_plaintext_and_logs(caplog, plaintext_length)

    ciphertext = b""
    with aws_encryption_sdk.stream(
        mode="encrypt", source=plaintext, key_provider=key_provider, frame_length=frame_size
    ) as encryptor:
        for line in encryptor:
            ciphertext += line

    _look_in_logs(caplog, plaintext)
    _error_check(capsys)


class NothingButRead(object):
    def __init__(self, data):
        self._data = data

    def read(self, size=-1):
        return self._data.read(size)


class NoTell(ObjectProxy):
    def tell(self):
        raise NotImplementedError("NoTell does not tell().")


class NoClosed(ObjectProxy):
    closed = NotImplemented


class NoClose(ObjectProxy):
    def close(self):
        raise NotImplementedError("NoClose does not close().")


@pytest.mark.parametrize("wrapping_class", (NoTell, NoClosed, NoClose, NothingButRead))
@pytest.mark.parametrize("frame_length", (0, 1024))
def test_cycle_minimal_source_stream_api(frame_length, wrapping_class):
    raw_plaintext = exact_length_plaintext(100)
    plaintext = wrapping_class(io.BytesIO(raw_plaintext))
    key_provider = fake_kms_key_provider()
    raw_ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=plaintext, key_provider=key_provider, frame_length=frame_length
    )
    ciphertext = wrapping_class(io.BytesIO(raw_ciphertext))
    decrypted, _decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=key_provider)
    assert raw_plaintext == decrypted


@pytest.mark.parametrize("wrapping_class", (NoTell, NoClosed, NoClose, NothingButRead))
@pytest.mark.parametrize("frame_length", (0, 1024))
def test_encrypt_minimal_source_stream_api(frame_length, wrapping_class):
    raw_plaintext = exact_length_plaintext(100)
    plaintext = wrapping_class(io.BytesIO(raw_plaintext))
    key_provider = fake_kms_key_provider()
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=plaintext, key_provider=key_provider, frame_length=frame_length
    )
    decrypted, _decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=key_provider)
    assert raw_plaintext == decrypted


@pytest.mark.parametrize("wrapping_class", (NoTell, NoClosed, NoClose, NothingButRead))
@pytest.mark.parametrize("frame_length", (0, 1024))
def test_decrypt_minimal_source_stream_api(frame_length, wrapping_class):
    plaintext = exact_length_plaintext(100)
    key_provider = fake_kms_key_provider()
    raw_ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=plaintext, key_provider=key_provider, frame_length=frame_length
    )
    ciphertext = wrapping_class(io.BytesIO(raw_ciphertext))
    decrypted, _decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=key_provider)
    assert plaintext == decrypted


def _assert_deprecated_but_not_yet_removed(logcap, instance, attribute_name, error_message, no_later_than):
    assert hasattr(instance, attribute_name)
    assert error_message in logcap.text
    assert aws_encryption_sdk.__version__ < no_later_than


def _assert_decrypted_and_removed(instance, attribute_name, removed_in):
    assert not hasattr(instance, attribute_name)
    assert aws_encryption_sdk.__version__ >= removed_in


@pytest.mark.parametrize("attribute, no_later_than", (("body_start", "1.4.0"), ("body_end", "1.4.0")))
def test_decryptor_deprecated_attributes(caplog, attribute, no_later_than):
    caplog.set_level(logging.WARNING)
    plaintext = exact_length_plaintext(100)
    key_provider = fake_kms_key_provider()
    ciphertext, _header = aws_encryption_sdk.encrypt(source=plaintext, key_provider=key_provider, frame_length=0)
    with aws_encryption_sdk.stream(mode="decrypt", source=ciphertext, key_provider=key_provider) as decryptor:
        decrypted = decryptor.read()

    assert decrypted == plaintext
    if aws_encryption_sdk.__version__ < no_later_than:
        _assert_deprecated_but_not_yet_removed(
            logcap=caplog,
            instance=decryptor,
            attribute_name=attribute,
            error_message="StreamDecryptor.{name} is deprecated and will be removed in {version}".format(
                name=attribute, version=no_later_than
            ),
            no_later_than=no_later_than,
        )
    else:
        _assert_decrypted_and_removed(instance=decryptor, attribute_name=attribute, removed_in=no_later_than)
