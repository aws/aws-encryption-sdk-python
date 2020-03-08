# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""
Example showing basic encryption and decryption of a value already in memory
using multiple KMS CMKs in multiple regions.
"""
import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKey, KMSMasterKeyProvider


def multiple_kms_cmk_regions(key_arn_1, key_arn_2, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string under multiple KMS customer master keys (CMKs) in multiple regions.

    :param str key_arn_1: Amazon Resource Name (ARN) of the KMS CMK
    :param str key_arn_2: Amazon Resource Name (ARN) of another KMS CMK
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    # Check that these keys are in different regions
    assert not key_arn_1.split(":")[3] == key_arn_2.split(":")[3]

    kwargs = dict(key_ids=[key_arn_1, key_arn_2])

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
        key_provider=KMSMasterKey(key_id=key_arn_1), source=ciphertext
    )
    plaintext_2, decrypted_message_header_2 = aws_encryption_sdk.decrypt(
        key_provider=KMSMasterKey(key_id=key_arn_2), source=ciphertext
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
