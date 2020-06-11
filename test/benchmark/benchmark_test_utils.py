# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper utilities for benchmark tests."""
import copy

import pytest

import aws_encryption_sdk
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager

ENCRYPTION_CONTEXT = {
    "encryption": "context",
    "is not": "secret",
    "but adds": "useful metadata",
    "that can help you": "be confident that",
    "the data you are handling": "is what you think it is",
}


def all_operations():
    return pytest.mark.parametrize(
        "operation",
        (
            pytest.param(aws_encryption_sdk.encrypt, id="encrypt only"),
            pytest.param(aws_encryption_sdk.decrypt, id="decrypt only"),
            pytest.param(encrypt_decrypt_cycle, id="encrypt decrypt cycle"),
        ),
    )


def encrypt_decrypt_cycle(**kwargs):
    encrypt_kwargs = copy.copy(kwargs)
    decrypt_kwargs = copy.copy(kwargs)
    for param in ("encryption_context", "frame_length", "source", "algorithm"):
        try:
            del decrypt_kwargs[param]
        except KeyError:
            pass

    encrypted = aws_encryption_sdk.encrypt(**encrypt_kwargs)
    decrypt_kwargs["source"] = encrypted.result
    aws_encryption_sdk.decrypt(**decrypt_kwargs)


def build_cmm(provider_builder, cache_messages):
    provider = provider_builder()
    if isinstance(provider, Keyring):
        provider_param = "keyring"
    else:
        provider_param = "master_key_provider"

    if cache_messages == 0:
        cmm = DefaultCryptoMaterialsManager(**{provider_param: provider})
    else:
        cmm = CachingCryptoMaterialsManager(
            max_age=6000.0,
            max_messages_encrypted=cache_messages,
            cache=LocalCryptoMaterialsCache(capacity=10),
            **{provider_param: provider}
        )

    return cmm


def run_benchmark(
    benchmark,
    provider_builder,
    operation,
    cache_messages=0,
    plaintext="foo",
    frame_length=1024,
    algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
):
    cmm = build_cmm(provider_builder, cache_messages)

    kwargs = dict(
        source=plaintext,
        materials_manager=cmm,
        encryption_context=copy.copy(ENCRYPTION_CONTEXT),
        frame_length=frame_length,
        algorithm=algorithm,
    )
    if operation is aws_encryption_sdk.decrypt:
        kwargs = dict(source=aws_encryption_sdk.encrypt(**kwargs).result, materials_manager=cmm,)
    benchmark.pedantic(target=operation, kwargs=kwargs, iterations=10, rounds=10)
