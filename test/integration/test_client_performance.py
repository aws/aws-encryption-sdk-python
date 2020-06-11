# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional performance test suite for ``aws_encryption_sdk``."""
import copy

import pytest

import aws_encryption_sdk
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager

from ..unit.unit_test_utils import (
    ephemeral_raw_aes_keyring,
    ephemeral_raw_aes_master_key,
    ephemeral_raw_rsa_keyring,
    ephemeral_raw_rsa_master_key,
)
from .integration_test_utils import build_aws_kms_keyring, setup_kms_master_key_provider

pytestmark = [pytest.mark.benchmark]
ENCRYPTION_CONTEXT = {
    "encryption": "context",
    "is not": "secret",
    "but adds": "useful metadata",
    "that can help you": "be confident that",
    "the data you are handling": "is what you think it is",
}


def _cycle(**kwargs):
    encrypt_kwargs = copy.copy(kwargs)
    decrypt_kwargs = copy.copy(kwargs)
    for param in ("encryption_context", "frame_length", "source"):
        try:
            del decrypt_kwargs[param]
        except KeyError:
            pass

    encrypted = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    decrypt_kwargs["source"] = encrypted.result
    aws_encryption_sdk.decrypt(**decrypt_kwargs)


@pytest.mark.parametrize(
    "provider_param, provider_builder",
    (
        pytest.param("keyring", ephemeral_raw_aes_keyring, id="Raw AES keyring"),
        pytest.param("key_provider", ephemeral_raw_aes_master_key, id="Raw AES master key"),
        pytest.param("keyring", ephemeral_raw_rsa_keyring, id="Raw RSA keyring"),
        pytest.param("key_provider", ephemeral_raw_rsa_master_key, id="Raw RSA master key"),
        pytest.param("keyring", build_aws_kms_keyring, id="AWS KMS keyring"),
        pytest.param("key_provider", setup_kms_master_key_provider, id="AWS KMS master key provider"),
    ),
)
@pytest.mark.parametrize(
    "cache_messages",
    (
        pytest.param(0, id="no cache"),
        pytest.param(1000000, id="cache and only miss once"),
        pytest.param(10, id="cache and only hit every 10"),
    ),
)
@pytest.mark.parametrize("plaintext, frame_length", (pytest.param("foo", 1024, id="single frame"),))
@pytest.mark.parametrize(
    "operation",
    (
        pytest.param(aws_encryption_sdk.encrypt, id="encrypt only"),
        pytest.param(aws_encryption_sdk.decrypt, id="decrypt only"),
        pytest.param(_cycle, id="encrypt decrypt cycle"),
    ),
)
def test_end2end_performance(
    benchmark, provider_param, provider_builder, cache_messages, plaintext, frame_length, operation
):
    provider = provider_builder()
    if cache_messages == 0:
        cmm = DefaultCryptoMaterialsManager(**{provider_param: provider})
    else:
        cmm = CachingCryptoMaterialsManager(
            max_age=6000.0,
            max_messages_encrypted=cache_messages,
            cache=LocalCryptoMaterialsCache(capacity=10),
            **{provider_param: provider}
        )
    kwargs = dict(
        source=plaintext,
        materials_provider=cmm,
        encryption_context=copy.copy(ENCRYPTION_CONTEXT),
        frame_length=frame_length,
    )
    if operation is aws_encryption_sdk.decrypt:
        kwargs = dict(source=aws_encryption_sdk.encrypt(**kwargs).result, materails_provider=cmm,)
    benchmark.pedantic(target=operation, kwargs=kwargs, iterations=100, rounds=10)
