# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test suite for `aws_encryption_sdk`."""
import io
import logging

import pytest

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX, Algorithm

from .integration_test_utils import build_aws_kms_keyring, get_cmk_arn, setup_kms_master_key_provider

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


def _generate_mkp():
    """Isolated inside a function to avoid calling get_cmk_arn during test discovery."""
    return setup_kms_master_key_provider().master_key(get_cmk_arn())


@pytest.mark.parametrize(
    "parameter_name, value_partial",
    (
        pytest.param("key_provider", setup_kms_master_key_provider, id="AWS KMS master key provider"),
        pytest.param("key_provider", _generate_mkp, id="AWS KMS master key"),
        pytest.param("keyring", build_aws_kms_keyring, id="AWS KMS keyring"),
    ),
)
def test_encrypt_verify_user_agent_in_logs(caplog, parameter_name, value_partial):
    caplog.set_level(level=logging.DEBUG)

    aws_encryption_sdk.encrypt(source=VALUES["plaintext_128"], **{parameter_name: value_partial()})

    assert USER_AGENT_SUFFIX in caplog.text


@pytest.mark.parametrize("frame_size", (pytest.param(0, id="unframed"), pytest.param(1024, id="1024 byte frame")))
@pytest.mark.parametrize("algorithm_suite", Algorithm)
@pytest.mark.parametrize(
    "encrypt_key_provider_param, encrypt_key_provider_partial",
    (
        pytest.param("key_provider", setup_kms_master_key_provider, id="encrypt with MKP"),
        pytest.param("keyring", build_aws_kms_keyring, id="encrypt with keyring"),
    ),
)
@pytest.mark.parametrize(
    "decrypt_key_provider_param, decrypt_key_provider_partial",
    (
        pytest.param("key_provider", setup_kms_master_key_provider, id="decrypt with MKP"),
        pytest.param("keyring", build_aws_kms_keyring, id="decrypt with keyring"),
    ),
)
@pytest.mark.parametrize(
    "encryption_context",
    (
        pytest.param({}, id="empty encryption context"),
        pytest.param(VALUES["encryption_context"], id="non-empty encryption context"),
    ),
)
@pytest.mark.parametrize(
    "plaintext",
    (
        pytest.param(VALUES["plaintext_128"], id="plaintext smaller than frame"),
        pytest.param(VALUES["plaintext_128"] * 100, id="plaintext larger than frame"),
    ),
)
def test_encrypt_decrypt_cycle_aws_kms(
    frame_size,
    algorithm_suite,
    encrypt_key_provider_param,
    encrypt_key_provider_partial,
    decrypt_key_provider_param,
    decrypt_key_provider_partial,
    encryption_context,
    plaintext,
):
    ciphertext, _ = aws_encryption_sdk.encrypt(
        source=plaintext,
        encryption_context=encryption_context,
        frame_length=frame_size,
        algorithm=algorithm_suite,
        **{encrypt_key_provider_param: encrypt_key_provider_partial()}
    )
    decrypted, _ = aws_encryption_sdk.decrypt(
        source=ciphertext, **{decrypt_key_provider_param: decrypt_key_provider_partial()}
    )
    assert decrypted == plaintext


@pytest.mark.parametrize(
    "plaintext",
    (
        pytest.param(VALUES["plaintext_128"], id="plaintext smaller than frame"),
        pytest.param(VALUES["plaintext_128"] * 100, id="plaintext larger than frame"),
    ),
)
def test_encrypt_decrypt_cycle_aws_kms_streaming(plaintext):
    keyring = build_aws_kms_keyring()
    ciphertext = b""
    with aws_encryption_sdk.stream(
        source=io.BytesIO(plaintext), keyring=keyring, mode="e", encryption_context=VALUES["encryption_context"],
    ) as encryptor:
        for chunk in encryptor:
            ciphertext += chunk
    header_1 = encryptor.header

    decrypted = b""
    with aws_encryption_sdk.stream(source=io.BytesIO(ciphertext), keyring=keyring, mode="d") as decryptor:
        for chunk in decryptor:
            decrypted += chunk
    header_2 = decryptor.header

    assert decrypted == plaintext
    assert header_1.encryption_context == header_2.encryption_context
