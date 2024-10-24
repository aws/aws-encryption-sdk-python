# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This is a performance test for creating the Raw RSA Master key provider."""

import os
import time

import click
import click.testing
import pytest
from tqdm import tqdm

from aws_encryption_sdk_performance_tests.master_key_providers.raw_rsa_master_key_provider import (
    create_key_provider,
    decrypt_using_key_provider,
    encrypt_using_key_provider,
)
from aws_encryption_sdk_performance_tests.utils.util import PerfTestUtils

MODULE_ABS_PATH = os.path.abspath(__file__)


@click.group()
def create_raw_rsa_key_provider():
    """Click group helper function"""


@create_raw_rsa_key_provider.command()
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/raw_rsa_key_provider_create')
def create(
    n_iters: int,
    output_file: str
):
    """Performance test for the create_key_provider function."""
    time_list = []
    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        create_key_provider()

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def encrypt_raw_rsa_key_provider():
    """Click group helper function"""


@encrypt_raw_rsa_key_provider.command()
@click.option('--plaintext_data_filename',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-2]) + '/resources/plaintext/plaintext-data-'
              + PerfTestUtils.DEFAULT_FILE_SIZE + '.dat')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/raw_rsa_key_provider_encrypt')
def encrypt(
    plaintext_data_filename: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the encrypt_using_key_provider function."""
    plaintext_data = PerfTestUtils.read_file(plaintext_data_filename)

    key_provider = create_key_provider()
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        encrypt_using_key_provider(plaintext_data, key_provider)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def decrypt_raw_rsa_key_provider():
    """Click group helper function"""


@decrypt_raw_rsa_key_provider.command()
@click.option('--ciphertext_data_filename',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-2]) + '/resources/ciphertext/raw_rsa/ciphertext-data-'
              + PerfTestUtils.DEFAULT_FILE_SIZE + '.ct')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/raw_rsa_key_provider_decrypt')
def decrypt(
    ciphertext_data_filename: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the decrypt_using_key_provider function."""
    ciphertext_data = PerfTestUtils.read_file(ciphertext_data_filename)

    key_provider = create_key_provider()
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        decrypt_using_key_provider(ciphertext_data, key_provider)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


raw_rsa_key_provider_test = click.CommandCollection(sources=[create_raw_rsa_key_provider,
                                                             encrypt_raw_rsa_key_provider,
                                                             decrypt_raw_rsa_key_provider])


@pytest.fixture
def runner():
    """Click runner"""
    return click.testing.CliRunner()


def test_create(runner):
    """Test the create_key_provider function"""
    result = runner.invoke(create_raw_rsa_key_provider.commands['create'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


def test_encrypt(runner):
    """Test the encrypt_using_key_provider function"""
    result = runner.invoke(encrypt_raw_rsa_key_provider.commands['encrypt'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


def test_decrypt(runner):
    """Test the decrypt_using_key_provider function"""
    result = runner.invoke(decrypt_raw_rsa_key_provider.commands['decrypt'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


if __name__ == "__main__":
    raw_rsa_key_provider_test()
