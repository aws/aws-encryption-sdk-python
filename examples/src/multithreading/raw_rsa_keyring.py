# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""This file contains methods to use for testing multi-threading for Raw RSA keyring."""
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.models import CreateRawRsaKeyringInput, PaddingScheme
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keys():
    """Generates a 4096-bit RSA public and private key pair

    Usage: generate_rsa_keys()
    """
    ssh_rsa_exponent = 65537
    bit_strength = 4096
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=ssh_rsa_exponent,
        key_size=bit_strength
    )

    # This example choses a particular type of encoding, format and encryption_algorithm
    # Users can choose the PublicFormat, PrivateFormat and encryption_algorithm that align most
    # with their use-cases
    public_key = key.public_key().public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key = key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=crypto_serialization.NoEncryption()
    )

    return public_key, private_key


def create_keyring(public_key, private_key):
    """Demonstrate how to create a Raw RSA keyring using the key pair.

    Usage: create_keyring(public_key, private_key)
    """
    key_name_space = "Some managed raw keys"
    key_name = "My 4096-bit RSA wrapping key"

    mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        config=MaterialProvidersConfig()
    )

    keyring_input: CreateRawRsaKeyringInput = CreateRawRsaKeyringInput(
        key_namespace=key_name_space,
        key_name=key_name,
        padding_scheme=PaddingScheme.OAEP_SHA256_MGF1,
        public_key=public_key,
        private_key=private_key
    )

    keyring: IKeyring = mat_prov.create_raw_rsa_keyring(
        input=keyring_input
    )

    return keyring
