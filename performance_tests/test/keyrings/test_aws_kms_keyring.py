# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This is a performance test for creating the AWS KMS keyring."""

import time

import click
from tqdm import tqdm

from aws_encryption_sdk_performance_tests.keyrings.aws_kms_keyring import (
    create_keyring,
    decrypt_using_keyring,
    encrypt_using_keyring,
)
from aws_encryption_sdk_performance_tests.utils.util import PerfTestUtils


@click.group()
def create_kms_keyring():
    """Click group helper function"""


@create_kms_keyring.command()
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='kms_keyring_create')
def create(
    kms_key_id: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the create_keyring function."""
    time_list = []
    for _ in tqdm(range(n_iters)):
        curr_time = time.time()

        create_keyring(kms_key_id)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.print_time_list_to_csv(time_list, output_file)


@click.group()
def encrypt_kms_keyring():
    """Click group helper function"""


@encrypt_kms_keyring.command()
@click.option('--plaintext_data_filename',
              prompt='Filename containing plaintext data you want to encrypt')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='kms_keyring_encrypt')
def encrypt(
    plaintext_data_filename: str,
    kms_key_id: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the encrypt_using_keyring function."""
    plaintext_data = PerfTestUtils.read_file(plaintext_data_filename)

    keyring = create_keyring(kms_key_id)
    time_list = []

    for _ in range(n_iters):
        curr_time = time.time()

        encrypt_using_keyring(plaintext_data, keyring)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.print_time_list_to_csv(time_list, output_file)


@click.group()
def decrypt_kms_keyring():
    """Click group helper function"""


@decrypt_kms_keyring.command()
@click.option('--ciphertext_data_filename',
              prompt='Filename containing ciphertext data you want to decrypt')
@click.option('--kms_key_id',
              default='arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f')
@click.option('--n_iters',
              default=PerfTestUtils.DEFAULT_N_ITERS)
@click.option('--output_file',
              default='kms_keyring_decrypt')
def decrypt(
    ciphertext_data_filename: str,
    kms_key_id: str,
    n_iters: int,
    output_file: str
):
    """Performance test for the decrypt_using_keyring function."""
    ciphertext_data = PerfTestUtils.read_file(ciphertext_data_filename)

    keyring = create_keyring(kms_key_id)
    time_list = []

    for _ in range(n_iters):
        curr_time = time.time()

        decrypt_using_keyring(ciphertext_data, keyring)

        # calculate elapsed time in milliseconds
        elapsed_time = (time.time() - curr_time) * 1000
        time_list.append(elapsed_time)

    PerfTestUtils.print_time_list_to_csv(time_list, output_file)


kms_keyring_test = click.CommandCollection(sources=[create_kms_keyring,
                                                    encrypt_kms_keyring,
                                                    decrypt_kms_keyring])


if __name__ == "__main__":
    kms_keyring_test()
