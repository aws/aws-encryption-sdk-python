# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Example showing basic encryption and decryption of a value already in memory
using multiple KMS CMKs in multiple regions.
"""
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyProvider


def run(aws_kms_generator_cmk, aws_kms_child_cmks, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under multiple KMS customer master keys (CMKs) in multiple regions.

    :param str aws_kms_generator_cmk: Amazon Resource Name (ARN) of the primary KMS CMK
    :param List[str] aws_kms_child_cmks: Additional Amazon Resource Names (ARNs) of secondary KMS CMKs
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    child_cmk = aws_kms_child_cmks[0]
    # Check that these keys are in different regions
    assert not aws_kms_generator_cmk.split(":")[3] == child_cmk.split(":")[3]

    kwargs = dict(key_ids=[aws_kms_generator_cmk, child_cmk])

    if botocore_session is not None:
        kwargs["botocore_session"] = botocore_session

    # Create master key provider using the ARNs of the keys and the session (botocore_session)
    kms_key_provider = KMSMasterKeyProvider(**kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, encrypted_message_header = aws_encryption_sdk.encrypt(
        key_provider=kms_key_provider, source=source_plaintext
    )

    # Check that both key ARNs are in the message headers
    assert len(encrypted_message_header.encrypted_data_keys) == 2

    # Decrypt the encrypted message using the AWS Encryption SDK. It returns the decrypted message and the header
    # Either of our keys can be used to decrypt the message
    plaintext_1, decrypted_message_header_1 = aws_encryption_sdk.decrypt(
        key_provider=KMSMasterKey(key_id=aws_kms_generator_cmk), source=ciphertext
    )
    plaintext_2, decrypted_message_header_2 = aws_encryption_sdk.decrypt(
        key_provider=KMSMasterKey(key_id=child_cmk), source=ciphertext
    )

    # Check that the original message and the decrypted message are the same
    if not isinstance(source_plaintext, bytes):
        plaintext_1 = plaintext_1.decode("utf-8")
        plaintext_2 = plaintext_2.decode("utf-8")
    assert source_plaintext == plaintext_1
    assert source_plaintext == plaintext_2

    # Check that the headers of the encrypted message and decrypted message match
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header_1.encryption_context.items()
    )
    assert all(
        pair in encrypted_message_header.encryption_context.items()
        for pair in decrypted_message_header_2.encryption_context.items()
    )
