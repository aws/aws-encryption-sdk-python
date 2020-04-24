# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
You might have used master key providers to protect your data keys
in an earlier version of the AWS Encryption SDK.
This example shows how to configure a keyring that behaves like an AWS KMS master key provider.

The AWS Encryption SDK provided an AWS KMS master key provider for
interacting with AWS Key Management Service (AWS KMS).
On encrypt, the AWS KMS master key provider behaves like the AWS KMS keyring
and encrypts with all CMKs that you identify.
However, on decrypt,
the AWS KMS master key provider reviews each encrypted data key (EDK).
If the EDK was encrypted under an AWS KMS CMK,
the AWS KMS master key provider attempts to decrypt it.
Whether decryption succeeds depends on permissions on the CMK.
This continues until the AWS KMS master key provider either runs out of EDKs
or succeeds in decrypting an EDK.
We have found that separating these two behaviors
makes the expected behavior clearer,
so that is what we did with the AWS KMS keyring and the AWS KMS discovery keyring.
However, as you migrate from master key providers to keyrings,
you might want a keyring that behaves like the AWS KMS master key provider.

For more examples of how to use the AWS KMS keyring,
see the ``keyring/aws_kms`` directory.
"""
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
from aws_encryption_sdk.keyrings.multi import MultiKeyring

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Sequence  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def run(aws_kms_cmk, aws_kms_additional_cmks, source_plaintext):
    # type: (str, Sequence[str], bytes) -> None
    """Demonstrate how to create a keyring that behaves like an AWS KMS master key provider.

    :param str aws_kms_cmk: The ARN of an AWS KMS CMK that protects data keys
    :param List[str] aws_kms_additional_cmks: Additional ARNs of secondary AWS KMS CMKs
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

    # This is the master key provider whose behavior we want to reproduce.
    #
    # When encrypting, this master key provider generates the data key using the first CMK in the list
    # and encrypts the data key using all specified CMKs.
    # However, when decrypting, this master key provider attempts to decrypt
    # any data keys that were encrypted under an AWS KMS CMK.
    master_key_provider_cmks = [aws_kms_cmk] + aws_kms_additional_cmks
    _master_key_provider_to_replicate = KMSMasterKeyProvider(  # noqa: intentionally never used
        key_ids=master_key_provider_cmks,
    )

    # Create a CMK keyring that encrypts and decrypts using the specified AWS KMS CMKs.
    #
    # This keyring reproduces the encryption behavior of the AWS KMS master key provider.
    #
    # The AWS KMS keyring requires that you explicitly identify the CMK
    # that you want the keyring to use to generate the data key.
    cmk_keyring = AwsKmsKeyring(generator_key_id=aws_kms_cmk, key_ids=aws_kms_additional_cmks)

    # Create an AWS KMS discovery keyring that will attempt to decrypt
    # any data keys that were encrypted under an AWS KMS CMK.
    discovery_keyring = AwsKmsKeyring(is_discovery=True)

    # Combine the CMK and discovery keyrings
    # to create a keyring that behaves like an AWS KMS master key provider.
    #
    # The CMK keyring reproduces the encryption behavior
    # and the discovery keyring reproduces the decryption behavior.
    # This also means that it does not matter if the CMK keyring fails to decrypt.
    # For example, if you configured the CMK keyring with aliases,
    # it works on encrypt but fails to match any encrypted data keys on decrypt
    # because the serialized key name is the resulting CMK ARN rather than the alias name.
    # However, because the discovery keyring attempts to decrypt any AWS KMS-encrypted
    # data keys that it finds, the message still decrypts successfully.
    keyring = MultiKeyring(generator=cmk_keyring, children=[discovery_keyring])

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
