# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Raw RSA keyring example."""
import os

import pytest

from ..src.raw_rsa_keyring_example import encrypt_and_decrypt_with_keyring, generate_rsa_keys

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring_without_user_defined_keys():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example.

    Here user doesn't provide the public and private keys
    """
    encrypt_and_decrypt_with_keyring()


def test_encrypt_and_decrypt_with_keyring_with_user_defined_keys():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example.

    Here user provides the public and private keys. To test this, we create the
    keys using the generate_rsa_keys function and write them to the file.
    Then we call the encrypt_and_decrypt_with_keyring function and pass them
    """
    # Generate the user keys for testing
    user_public_key, user_private_key = generate_rsa_keys()

    # Convert the keys to strings
    user_public_key = user_public_key.decode('utf-8')
    user_private_key = user_private_key.decode('utf-8')

    test_keyrings_directory = 'test_keyrings'
    if not os.path.exists(test_keyrings_directory):
        os.makedirs(test_keyrings_directory)

    # Define the file names for the keys
    user_public_key_file_name = test_keyrings_directory + '/user_public_key_file_name.pem'
    user_private_key_file_name = test_keyrings_directory + '/user_private_key_file_name.pem'

    # Write the public key to the file
    with open(user_public_key_file_name, "w", encoding="utf-8") as f:
        f.write(user_public_key)

    # Write the private key to the file
    with open(user_private_key_file_name, "w", encoding="utf-8") as f:
        f.write(user_private_key)

    encrypt_and_decrypt_with_keyring(public_key_file_name=user_public_key_file_name,
                                     private_key_file_name=user_private_key_file_name)


def test_encrypt_and_decrypt_fails_if_user_provides_only_public_key():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example.

    Here user provides only the public key. The program should throw an Value error
    as this example requires the user to either provide both private and public keys to
    test both encryption and decryption, or not provide any keys and the example generates both
    """
    # Generate the user keys for testing
    user_public_key, user_private_key = generate_rsa_keys()

    # Convert the public key to string
    user_public_key = user_public_key.decode('utf-8')

    test_keyrings_directory = 'test_keyrings'
    if not os.path.exists(test_keyrings_directory):
        os.makedirs(test_keyrings_directory)

    # Define the file name for the public key
    user_public_key_file_name = test_keyrings_directory + '/user_public_key_file_name.pem'

    # Write the public key to the file
    with open(user_public_key_file_name, "w", encoding="utf-8") as f:
        f.write(user_public_key)

    try:
        encrypt_and_decrypt_with_keyring(public_key_file_name=user_public_key_file_name)

        raise AssertionError("encrypt_and_decrypt_with_keyring should raise an error")
    except ValueError:
        pass


def test_encrypt_and_decrypt_fails_if_user_provides_only_private_key():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example.

    Here user provides only the private key. The program should throw an Value error
    as this example requires the user to either provide both private and public keys to
    test both encryption and decryption, or not provide any keys and the example generates both
    """
    # Generate the user keys for testing
    user_public_key, user_private_key = generate_rsa_keys()

    # Convert the private key to string
    user_private_key = user_private_key.decode('utf-8')

    test_keyrings_directory = 'test_keyrings'
    if not os.path.exists(test_keyrings_directory):
        os.makedirs(test_keyrings_directory)

    # Define the file name for the private key
    user_private_key_file_name = test_keyrings_directory + '/user_private_key_file_name.pem'

    # Write the private key to the file
    with open(user_private_key_file_name, "w", encoding="utf-8") as f:
        f.write(user_private_key)

    try:
        encrypt_and_decrypt_with_keyring(private_key_file_name=user_private_key_file_name)

        raise AssertionError("encrypt_and_decrypt_with_keyring should raise an error")
    except ValueError:
        pass
