# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This is a performance test for creating a Caching CMM."""

import os
import time

import click
import click.testing
import pytest
from tqdm import tqdm

from aws_encryption_sdk_performance_tests.master_key_providers.caching_cmm import (
    create_cmm,
    decrypt_using_cmm,
    encrypt_using_cmm,
)
from aws_encryption_sdk_performance_tests.utils.util import PerfTestUtils

MODULE_ABS_PATH = os.path.abspath(__file__)


@click.group()
def create_caching_cmm():
    """Click group helper function"""


@create_caching_cmm.command()
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f')
@click.option('--max_age_in_cache',
              default=10.0)
@click.option('--cache_capacity',
              default=10)
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/caching_cmm_create')
def create(
    kms_key_id: str,
    max_age_in_cache: float,
    cache_capacity: int,
    n_iters: int,
    output_file: str
):
    """Performance test for the create_cmm function."""
    time_list = []
    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        create_cmm(kms_key_id, max_age_in_cache, cache_capacity)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def encrypt_caching_cmm():
    """Click group helper function"""


@encrypt_caching_cmm.command()
@click.option('--plaintext_data_filename',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-2]) + '/resources/plaintext/plaintext-data-'
              + PerfTestUtils.DEFAULT_FILE_SIZE + '.dat')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f')
@click.option('--max_age_in_cache',
              default=10.0)
@click.option('--cache_capacity',
              default=10)
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/caching_cmm_encrypt')
def encrypt(
    plaintext_data_filename: str,
    kms_key_id: str,
    max_age_in_cache: float,
    cache_capacity: int,
    n_iters: int,
    output_file: str
):
    """Performance test for the encrypt_using_cmm function."""
    plaintext_data = PerfTestUtils.read_file(plaintext_data_filename)

    caching_cmm = create_cmm(kms_key_id, max_age_in_cache, cache_capacity)
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        encrypt_using_cmm(plaintext_data, caching_cmm)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def decrypt_caching_cmm():
    """Click group helper function"""


@decrypt_caching_cmm.command()
@click.option('--ciphertext_data_filename',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-2]) + '/resources/ciphertext/caching_cmm/ciphertext-data-'
              + PerfTestUtils.DEFAULT_FILE_SIZE + '.ct')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f')
@click.option('--max_age_in_cache',
              default=10.0)
@click.option('--cache_capacity',
              default=10)
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/caching_cmm_decrypt')
def decrypt(
    ciphertext_data_filename: str,
    kms_key_id: str,
    max_age_in_cache: float,
    cache_capacity: int,
    n_iters: int,
    output_file: str
):
    """Performance test for the decrypt_using_cmm function."""
    ciphertext_data = PerfTestUtils.read_file(ciphertext_data_filename)

    caching_cmm = create_cmm(kms_key_id, max_age_in_cache, cache_capacity)
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        decrypt_using_cmm(ciphertext_data, caching_cmm)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


caching_cmm_test = click.CommandCollection(sources=[create_caching_cmm,
                                                    encrypt_caching_cmm,
                                                    decrypt_caching_cmm])


@pytest.fixture
def runner():
    """Click runner"""
    return click.testing.CliRunner()


def test_create(runner):
    """Test the create_cmm function"""
    result = runner.invoke(create_caching_cmm.commands['create'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


def test_encrypt(runner):
    """Test the encrypt_using_cmm function"""
    result = runner.invoke(encrypt_caching_cmm.commands['encrypt'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


def test_decrypt(runner):
    """Test the decrypt_using_cmm function"""
    result = runner.invoke(decrypt_caching_cmm.commands['decrypt'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


if __name__ == "__main__":
    caching_cmm_test()
