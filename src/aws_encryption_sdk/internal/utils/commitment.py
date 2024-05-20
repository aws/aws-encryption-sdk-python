# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper functions for validating commitment policies and algorithms for the AWS Encryption SDK."""
from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.identifiers import CommitmentPolicy

TROUBLESHOOTING_URL = "https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html"


def validate_commitment_policy_on_encrypt(commitment_policy, algorithm):
    """Validates that the provided algorithm does not violate the commitment policy for an encrypt request."""
    if commitment_policy == CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT and (
        algorithm is not None and algorithm.is_committing()
    ):
        error_message = (
            "Configuration conflict. Cannot encrypt due to {} requiring only non-committed messages. "
            "Algorithm ID was {}. See: " + TROUBLESHOOTING_URL
        )
        raise ActionNotAllowedError(error_message.format(commitment_policy, algorithm.algorithm_id))
    if commitment_policy in (
        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    ):
        if algorithm is not None and not algorithm.is_committing():
            error_message = (
                "Configuration conflict. Cannot encrypt due to {} requiring only committed messages. "
                "Algorithm ID was {}. See: " + TROUBLESHOOTING_URL
            )
            raise ActionNotAllowedError(error_message.format(commitment_policy, algorithm.algorithm_id))


def validate_commitment_policy_on_decrypt(commitment_policy, algorithm):
    """Validates that the provided algorithm does not violate the commitment policy for a decrypt request."""
    if commitment_policy == CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT and not algorithm.is_committing():
        error_message = (
            "Configuration conflict. Cannot decrypt due to {} requiring only committed messages. Algorithm ID was {}. "
            "See: " + TROUBLESHOOTING_URL
        )
        raise ActionNotAllowedError(error_message.format(commitment_policy, algorithm.algorithm_id))
