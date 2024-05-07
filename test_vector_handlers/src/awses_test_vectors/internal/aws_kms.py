# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper utilities for interacting with AWS KMS."""
try:
    from aws_encryption_sdk.identifiers import AlgorithmSuite
except ImportError:
    from aws_encryption_sdk.identifiers import Algorithm as AlgorithmSuite
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryAwsKmsMasterKeyProvider,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
    StrictAwsKmsMasterKeyProvider,
)

from awses_test_vectors.internal.defaults import ENCODING

# This lets us easily use a single boto3 client per region for all KMS master keys.
KMS_MASTER_KEY_PROVIDER = DiscoveryAwsKmsMasterKeyProvider()
KMS_MRK_AWARE_MASTER_KEY_PROVIDER = MRKAwareDiscoveryAwsKmsMasterKeyProvider(discovery_region="us-west-2")


def arn_from_key_id(key_id):
    # type: (str) -> str
    """Determine the KMS CMK Arn for the identified key ID.

    To avoid needing additional KMS permissions, we just call ``generate_data_key``
    using a master key identified by ``key_id``.

    :param str key_id: Original key ID
    :returns: Full Arn for KMS CMK that key ID identifies
    :rtype: str
    """
    provider = StrictAwsKmsMasterKeyProvider(key_ids=[key_id])
    encrypted_data_key = provider.master_key(key_id.encode(ENCODING)).generate_data_key(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, encryption_context={}
    )
    return encrypted_data_key.key_provider.key_info.decode(ENCODING)
