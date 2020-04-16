# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
By default, the AWS KMS keyring uses the default configurations
for all AWS KMS clients and uses the default discoverable credentials.
If you need to change this configuration,
you can configure the client supplier.

This example shows how to use custom-configured clients with the AWS KMS keyring.

https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html#use-kms-keyring

For an example of how to use the AWS KMS keyring with CMKs in multiple regions,
see the ``keyring/aws_kms/multiple_regions`` example.

For another example of how to use the AWS KMS keyring with custom client configuration,
see the ``keyring/aws_kms/custom_client_supplier`` example.

For examples of how to use the AWS KMS keyring in discovery mode on decrypt,
see the ``keyring/aws_kms/discovery_decrypt``,
``keyring/aws_kms/discovery_decrypt_in_region_only``,
and ``keyring/aws_kms/discovery_decrypt_with_preferred_region`` examples.
"""
from botocore.config import Config
from botocore.session import Session

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import USER_AGENT_SUFFIX
from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
from aws_encryption_sdk.keyrings.aws_kms.client_suppliers import DefaultClientSupplier


def run(aws_kms_cmk, source_plaintext):
    # type: (str, bytes) -> None
    """Demonstrate an encrypt/decrypt cycle using an AWS KMS keyring with custom AWS KMS client configuration.

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

    # Prepare your custom configuration values.
    #
    # Set your custom connection timeout value.
    # https://botocore.amazonaws.com/v1/documentation/api/latest/reference/config.html
    custom_client_config = Config(connect_timeout=10.0, user_agent_extra=USER_AGENT_SUFFIX)
    # For this example we will just use the default botocore session configuration
    # but if you need to, you can set custom credentials in the botocore session.
    custom_session = Session()

    # Use your custom configuration values to configure your client supplier.
    client_supplier = DefaultClientSupplier(botocore_session=custom_session, client_config=custom_client_config)

    # Create the keyring that determines how your data keys are protected,
    # providing the client supplier that you created.
    keyring = AwsKmsKeyring(generator_key_id=aws_kms_cmk, client_supplier=client_supplier)

    # Encrypt your plaintext data.
    ciphertext, _encrypt_header = aws_encryption_sdk.encrypt(
        source=source_plaintext, encryption_context=encryption_context, keyring=keyring
    )

    # Demonstrate that the ciphertext and plaintext are different.
    assert ciphertext != source_plaintext

    # Decrypt your encrypted data using the same keyring you used on encrypt.
    #
    # You do not need to specify the encryption context on decrypt
    # because the header of the encrypted message includes the encryption context.
    decrypted, decrypt_header = aws_encryption_sdk.decrypt(source=ciphertext, keyring=keyring)

    # Demonstrate that the decrypted plaintext is identical to the original plaintext.
    assert decrypted == source_plaintext

    # Verify that the encryption context used in the decrypt operation includes
    # the encryption context that you specified when encrypting.
    # The AWS Encryption SDK can add pairs, so don't require an exact match.
    #
    # In production, always use a meaningful encryption context.
    assert set(encryption_context.items()) <= set(decrypt_header.encryption_context.items())
