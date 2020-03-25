# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
By default, the KMS keyring uses a client supplier that
supplies a client with the same configuration for every region.
If you need different behavior, you can write your own client supplier.

You might use this 
if you need different credentials in different AWS regions.
This might be because you are crossing partitions (ex: ``aws`` and ``aws-cn``)
or if you are working with regions that have separate authentication silos
like ``ap-east-1`` and ``me-south-1``.

This example shows how to create a client supplier
that will supply KMS clients with valid credentials for the target region
even when working with regions that need different credentials.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring

For an example of how to use the KMS keyring with CMKs in multiple regions,
see the ``keyring/aws_kms/multiple_regions`` example.

For another example of how to use the KMS keyring with a custom client configuration,
see the ``keyring/aws_kms/custom_kms_client_config`` example.

For examples of how to use the KMS keyring in discovery mode on decrypt,
see the ``keyring/aws_kms/discovery_decrypt``,
``keyring/aws_kms/discovery_decrypt_in_region_only``,
and ``keyring/aws_kms/discovery_decrypt_with_preferred_region`` examples.
"""
from botocore.client import BaseClient
from botocore.session import Session

import aws_encryption_sdk
from aws_encryption_sdk.keyrings.aws_kms import KmsKeyring
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import ClientSupplier, DefaultClientSupplier

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only need these imports when running the mypy checks
    pass


class MultiPartitionClientSupplier(ClientSupplier):
    """Client supplier that supplies clients across AWS partitions and identity silos."""

    def __init__(self):
        """Set up default client suppliers for identity silos."""
        self._china_supplier = DefaultClientSupplier(botocore_session=Session(profile="china"))
        self._middle_east_supplier = DefaultClientSupplier(botocore_session=Session(profile="middle-east"))
        self._hong_kong_supplier = DefaultClientSupplier(botocore_session=Session(profile="hong-kong"))
        self._default_supplier = DefaultClientSupplier()

    def __call__(self, region_name):
        # type: (Union[None, str]) -> BaseClient
        """Return a client for the requested region.

        :rtype: BaseClient
        """
        if region_name.startswith("cn-"):
            return self._china_supplier(region_name)

        if region_name.startswith("me-"):
            return self._middle_east_supplier(region_name)

        if region_name == "ap-east-1":
            return self._hong_kong_supplier(region_name)

        return self._default_supplier(region_name)


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using a KMS keyring with a custom client supplier.

    :param str aws_kms_cmk: The ARN of an AWS KMS CMK that protects data keys
    :param bytes source_plaintext: Plaintext to encrypt
    """
    # Prepare your encryption context.
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
    encryption_context = {
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    # Create the keyring that determines how your data keys are protected.
    keyring = KmsKeyring(generator_key_id=aws_kms_cmk, client_supplier=MultiPartitionClientSupplier())

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same keyring you used on encrypt.
    #
    # We do not need to specify the encryption context on decrypt
    # because the header message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
