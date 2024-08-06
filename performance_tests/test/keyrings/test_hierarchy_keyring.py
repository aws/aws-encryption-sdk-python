# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This is a performance test for creating the hierarchy keyring."""

import os
import time

import click
import click.testing
import pytest
from tqdm import tqdm

from aws_encryption_sdk_performance_tests.keyrings.hierarchy_keyring import (
    create_keyring,
    decrypt_using_keyring,
    encrypt_using_keyring,
)
from aws_encryption_sdk_performance_tests.utils.util import PerfTestUtils

MODULE_ABS_PATH = os.path.abspath(__file__)


@click.group()
def create_hierarchy_keyring():
    """Click group helper function"""


@create_hierarchy_keyring.command()
@click.option('--key_store_table_name',
              default='KeyStoreDdbTable')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/hierarchy_keyring_create')
def create(
    key_store_table_name: str,
    kms_key_id: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the create_keyring function."""
    time_list = []
    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        create_keyring(key_store_table_name, key_store_table_name, kms_key_id)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def encrypt_hierarchy_keyring():
    """Click group helper function"""


@encrypt_hierarchy_keyring.command()
@click.option('--plaintext_data_filename',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-2]) + '/resources/plaintext/plaintext-data-'
              + PerfTestUtils.DEFAULT_FILE_SIZE + '.dat')
@click.option('--key_store_table_name',
              default='KeyStoreDdbTable')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/hierarchy_keyring_encrypt')
def encrypt(
    plaintext_data_filename: str,
    key_store_table_name: str,
    kms_key_id: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the encrypt_using_keyring function."""
    plaintext_data = PerfTestUtils.read_file(plaintext_data_filename)

    keyring = create_keyring(key_store_table_name, key_store_table_name, kms_key_id)
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        encrypt_using_keyring(plaintext_data, keyring)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


@click.group()
def decrypt_hierarchy_keyring():
    """Click group helper function"""


@decrypt_hierarchy_keyring.command()
@click.option('--ciphertext_data_filename',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-2]) + '/resources/ciphertext/hierarchy/ciphertext-data-'
              + PerfTestUtils.DEFAULT_FILE_SIZE + '.ct')
@click.option('--key_store_table_name',
              default='KeyStoreDdbTable')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='/'.join(MODULE_ABS_PATH.split("/")[:-3]) + '/results/hierarchy_keyring_decrypt')
def decrypt(
    ciphertext_data_filename: str,
    key_store_table_name: str,
    kms_key_id: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the decrypt_using_keyring function."""
    ciphertext_data = PerfTestUtils.read_file(ciphertext_data_filename)

    keyring = create_keyring(key_store_table_name, key_store_table_name, kms_key_id)
    time_list = []

    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        decrypt_using_keyring(ciphertext_data, keyring)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.write_time_list_to_csv(time_list, output_file)


hierarchy_keyring_test = click.CommandCollection(sources=[create_hierarchy_keyring,
                                                          encrypt_hierarchy_keyring,
                                                          decrypt_hierarchy_keyring])


@pytest.fixture
def runner():
    """Click runner"""
    return click.testing.CliRunner()


def test_create(runner):
    """Test the create_keyring function"""
    result = runner.invoke(create_hierarchy_keyring.commands['create'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


def test_encrypt(runner):
    """Test the encrypt_using_keyring function"""
    result = runner.invoke(encrypt_hierarchy_keyring.commands['encrypt'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


def test_decrypt(runner):
    """Test the decrypt_using_keyring function"""
    result = runner.invoke(decrypt_hierarchy_keyring.commands['decrypt'],
                           ['--n_iters', PerfTestUtils.DEFAULT_TESTING_N_ITERS])
    assert result.exit_code == 0


if __name__ == "__main__":
    hierarchy_keyring_test()
