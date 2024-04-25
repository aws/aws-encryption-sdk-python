# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the Raw RSA keyring example."""
import pytest

from ...src.keyrings.raw_rsa_keyring_example import encrypt_and_decrypt_with_keyring, generate_rsa_keys

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring_without_user_defined_keys():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example
    where user doesn't provide the public and private keys
    """
    encrypt_and_decrypt_with_keyring()


def test_encrypt_and_decrypt_with_keyring_with_user_defined_keys():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example
    where user provides the public and private keys. To test this, we create the
    keys using the generate_rsa_keys function
    """
    user_public_key, user_private_key = generate_rsa_keys()
    encrypt_and_decrypt_with_keyring(public_key=user_public_key, private_key=user_private_key)


def test_encrypt_and_decrypt_fails_if_user_provides_only_public_key():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example
    where user provides only the public key. The program should throw an Assertion error
    as this example requires the user to either provide both private and public keys to
    test both encryption and decryption, or not provide any keys and the example generates both
    """
    user_public_key, user_private_key = generate_rsa_keys()
    try:
        encrypt_and_decrypt_with_keyring(public_key=user_public_key)

        raise AssertionError("encrypt_and_decrypt_with_keyring should raise an error")
    except AssertionError:
        pass


def test_encrypt_and_decrypt_fails_if_user_provides_only_private_key():
    """Test function for encrypt and decrypt using the Raw RSA Keyring example
    where user provides only the private key. The program should throw an Assertion error
    as this example requires the user to either provide both private and public keys to
    test both encryption and decryption, or not provide any keys and the example generates both
    """
    user_public_key, user_private_key = generate_rsa_keys()
    try:
        encrypt_and_decrypt_with_keyring(private_key=user_private_key)

        raise AssertionError("encrypt_and_decrypt_with_keyring should raise an error")
    except AssertionError:
        pass
