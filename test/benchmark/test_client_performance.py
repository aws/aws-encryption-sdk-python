# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional performance test suite for ``aws_encryption_sdk``."""
import os

import pytest

from aws_encryption_sdk.identifiers import AlgorithmSuite

from ..integration.integration_test_utils import build_aws_kms_keyring, setup_kms_master_key_provider
from ..unit.unit_test_utils import (
    ephemeral_raw_aes_keyring,
    ephemeral_raw_aes_master_key,
    ephemeral_raw_rsa_keyring,
    ephemeral_raw_rsa_master_key,
)
from .benchmark_test_utils import all_operations, run_benchmark

pytestmark = [pytest.mark.benchmark]

PLAINTEXTS = {
    "SMALL": os.urandom(32),  # 32B
    "LARGE": os.urandom(1024 * 1024),  # 1MiB
    "VERY_LARGE": os.urandom(10 * 1024 * 1024),  # 10MiB
}


@pytest.mark.parametrize("algorithm_suite", AlgorithmSuite)
@all_operations()
def test_compare_algorithm_suite_performance(benchmark, algorithm_suite, operation):
    """Compare the affect of algorithm suite on performance.
    Use the Raw AES keyring as a baseline keyring.
    """
    run_benchmark(
        benchmark=benchmark, provider_builder=ephemeral_raw_aes_keyring, operation=operation, algorithm=algorithm_suite
    )


@pytest.mark.parametrize(
    "cache_messages",
    (
        pytest.param(0, id="no cache"),
        pytest.param(1000000, id="cache and only miss once"),
        pytest.param(10, id="cache and miss every 10"),
    ),
)
@all_operations()
def test_compare_caching_performance(benchmark, operation, cache_messages):
    """Compare the affect of caching on performance.
    Use the Raw AES keyring as a baseline keyring.
    """
    run_benchmark(
        benchmark=benchmark,
        provider_builder=ephemeral_raw_aes_keyring,
        operation=operation,
        cache_messages=cache_messages,
    )


@pytest.mark.parametrize(
    "plaintext, frame_length",
    (
        pytest.param("SMALL", 0, id="small message, unframed"),
        pytest.param("SMALL", 128, id="small message, single frame"),
        pytest.param("LARGE", 1024 * 1024 * 1024, id="large message, single frame"),
        pytest.param("LARGE", 102400, id="large message, few large frames"),
        pytest.param("LARGE", 1024, id="large message, many small frames"),
    ),
)
@all_operations()
def test_compare_framing_performance(benchmark, operation, plaintext, frame_length):
    """Compare the affect of framing and on performance.
    Use the Raw AES keyring as a baseline keyring.
    """
    run_benchmark(
        benchmark=benchmark,
        provider_builder=ephemeral_raw_aes_keyring,
        operation=operation,
        plaintext=PLAINTEXTS[plaintext],
        frame_length=frame_length,
    )


def _frame_sizes():
    for frame_kb in (2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 10240):
        yield pytest.param(frame_kb * 1024, id="{} kiB frame".format(frame_kb))


@pytest.mark.parametrize(
    "plaintext", (pytest.param("LARGE", id="1MiB plaintext"), pytest.param("VERY_LARGE", id="10MiB plaintext"),),
)
@pytest.mark.parametrize("frame_length", _frame_sizes())
@all_operations()
def test_compare_frame_size_performance(benchmark, operation, plaintext, frame_length):
    """Compare the affect of framing and on performance.
    Use the Raw AES keyring as a baseline keyring.
    """
    run_benchmark(
        benchmark=benchmark,
        provider_builder=ephemeral_raw_aes_keyring,
        operation=operation,
        plaintext=PLAINTEXTS[plaintext],
        frame_length=frame_length,
    )


@pytest.mark.parametrize(
    "provider_builder",
    (
        pytest.param(ephemeral_raw_aes_keyring, id="Raw AES keyring"),
        pytest.param(ephemeral_raw_aes_master_key, id="Raw AES master key"),
        pytest.param(ephemeral_raw_rsa_keyring, id="Raw RSA keyring"),
        pytest.param(ephemeral_raw_rsa_master_key, id="Raw RSA master key"),
        pytest.param(build_aws_kms_keyring, id="AWS KMS keyring", marks=pytest.mark.integ),
        pytest.param(setup_kms_master_key_provider, id="AWS KMS master key provider", marks=pytest.mark.integ),
    ),
)
@all_operations()
def test_compare_keyring_performance(benchmark, provider_builder, operation):
    """Compare the performance of different keyrings and master key providers."""
    run_benchmark(benchmark=benchmark, provider_builder=provider_builder, operation=operation)
