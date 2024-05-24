# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This is a performance test for creating the Raw AES keyring."""

import time

import click
import click.testing
import pytest
from tqdm import tqdm

from aws_encryption_sdk_performance_tests.keyrings.raw_aes_keyring import (
    create_keyring,
    decrypt_using_keyring,
    encrypt_using_keyring,
)
from aws_encryption_sdk_performance_tests.utils.util import PerfTestUtils


@click.group()
def create_raw_aes_keyring():
    """Click group helper function"""


@create_raw_aes_keyring.command()
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='raw_aes_keyring_create')
def create(
    n_iters: int,
    output_file: str
):
    """Performance test for the create_keyring function."""
    time_list = []
    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        create_keyring()

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def encrypt_raw_aes_keyring():
    """Click group helper function"""


@encrypt_raw_aes_keyring.command()
@click.option('--plaintext_data_filename',
              default='test/resources/plaintext/plaintext-data-' + PerfTestUtils.DEFAULT_FILE_SIZE + '.dat',
              prompt='Filename containing plaintext data you want to encrypt')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='raw_aes_keyring_encrypt')
def encrypt(
    plaintext_data_filename: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the encrypt_using_keyring function."""
    plaintext_data = PerfTestUtils.read_file(plaintext_data_filename)

    keyring = create_keyring()
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        encrypt_using_keyring(plaintext_data, keyring)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def decrypt_raw_aes_keyring():
    """Click group helper function"""


@decrypt_raw_aes_keyring.command()
@click.option('--ciphertext_data_filename',
              default='test/resources/ciphertext/raw_aes/ciphertext-data-' + PerfTestUtils.DEFAULT_FILE_SIZE + '.ct',
              prompt='Filename containing ciphertext data you want to decrypt')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='raw_aes_keyring_decrypt')
def decrypt(
    ciphertext_data_filename: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the decrypt_using_keyring function."""
    ciphertext_data = PerfTestUtils.read_file(ciphertext_data_filename)

    keyring = create_keyring()
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        decrypt_using_keyring(ciphertext_data, keyring)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


raw_aes_keyring_test = click.CommandCollection(sources=[create_raw_aes_keyring,
                                                        encrypt_raw_aes_keyring,
                                                        decrypt_raw_aes_keyring])


@pytest.fixture
def runner():
    """Click runner"""
    return click.testing.CliRunner()


def test_create(runner):
    """Test the create_keyring function"""
    result = runner.invoke(create_raw_aes_keyring.commands['create'], ['--n_iters', 1])
    assert result.exit_code == 0


def test_encrypt(runner):
    """Test the encrypt_using_keyring function"""
    result = runner.invoke(encrypt_raw_aes_keyring.commands['encrypt'], ['--n_iters', 1])
    assert result.exit_code == 0


def test_decrypt(runner):
    """Test the decrypt_using_keyring function"""
    result = runner.invoke(decrypt_raw_aes_keyring.commands['decrypt'], ['--n_iters', 1])
    assert result.exit_code == 0


if __name__ == "__main__":
    raw_aes_keyring_test()
