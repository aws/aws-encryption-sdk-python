# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Example showing encryption of a value already in memory using one KMS CMK, then decryption of the ciphertext using
a DiscoveryAwsKmsMasterKeyProvider.
"""

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryFilter,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
    MRKAwareStrictAwsKmsMasterKeyProvider,
)


def encrypt_decrypt(mrk_arn, mrk_arn_second_region, source_plaintext):
    """Illustrates usage of KMS Multi-Region Keys.

    :param str mrk_arn: Amazon Resource Name (ARN) of the first KMS MRK
    :param str mrk_arn_second_region: Amazon Resource Name (ARN) of a related KMS MRK in a different region
    :param bytes source_plaintext: Data to encrypt
    """
    # Encrypt in the first region

    # Set up an encryption client with an explicit commitment policy. Note that if you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # For this example, set mrk_arn to be a Multi-Region key.
    # Multi-Region keys have a distinctive key ID that begins with 'mrk'.
    # For example: "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab".

    # Create a Strict Multi-Region Key Aware Master Key Provider which targets the Multi-Region key ARN.
    kwargs = dict(key_ids=[mrk_arn])
    strict_key_provider = MRKAwareStrictAwsKmsMasterKeyProvider(**kwargs)

    # Encrypt the plaintext using the AWS Encryption SDK. It returns the encrypted message and the header
    ciphertext, _ = client.encrypt(source=source_plaintext, key_provider=strict_key_provider)

    # Decrypt in a second region

    # For this example, set mrk_arn_second_region to be Multi-Region key related to key_arn.
    # Related multi-Region keys have the same key ID. Their key ARNs differs only in the Region field.
    # For example: "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab"

    # Create a Strict Multi-Region Key Aware Master Key Provider which targets the Multi-Region key in the second region
    kwargs = dict(key_ids=[mrk_arn_second_region])
    strict_key_provider_region_2 = MRKAwareStrictAwsKmsMasterKeyProvider(**kwargs)

    # Decrypt your ciphertext
    plaintext, _ = client.decrypt(source=ciphertext, key_provider=strict_key_provider_region_2)

    # Verify that the original message and the decrypted message are the same
    assert source_plaintext == plaintext

    # Decrypt in discovery mode in a second region

    # First determine what region you want to perform discovery in, as well as what
    # accounts and partition you want to allow if using a Discovery Filter.
    # In this example, we just want to use whatever region, account, and partition
    # our second key is in, in order to ensure we can discover it.
    # Note that the ARN itself is never used in the configuration.
    arn = arn_from_str(mrk_arn_second_region)
    discovery_region = arn.region
    filter_accounts = [arn.account_id]
    filter_partition = arn.partition

    # Configure a Discovery Region and optional Discovery Filter
    decrypt_kwargs = dict(
        discovery_filter=DiscoveryFilter(account_ids=filter_accounts, partition=filter_partition),
        discovery_region=discovery_region,
    )

    # Create an MRK-aware master key provider in discovery mode that targets the second region.
    # This will cause the provider to try to decrypt using this region whenever it encounters an MRK.
    discovery_key_provider = MRKAwareDiscoveryAwsKmsMasterKeyProvider(**decrypt_kwargs)

    # Decrypt the encrypted message using the AWS Encryption SDK. It returns the decrypted message and the header.
    plaintext, _ = client.decrypt(source=ciphertext, key_provider=discovery_key_provider)

    # Verify that the original message and the decrypted message are the same
    assert source_plaintext == plaintext
