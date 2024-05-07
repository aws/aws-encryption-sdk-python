# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper functions for validating signature policies and algorithms for the AWS Encryption SDK."""

from enum import Enum

from aws_encryption_sdk.exceptions import ActionNotAllowedError


class SignaturePolicy(Enum):
    """Controls algorithm suites that can be used on encryption and decryption."""

    ALLOW_ENCRYPT_ALLOW_DECRYPT = 0
    ALLOW_ENCRYPT_FORBID_DECRYPT = 1


def validate_signature_policy_on_decrypt(signature_policy, algorithm):
    """Validates that the provided algorithm does not violate the signature policy for a decrypt request."""
    if signature_policy == SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT and algorithm.is_signing():
        error_message = (
            "Configuration conflict. Cannot decrypt signed message in decrypt-unsigned mode. Algorithm ID was {}. "
        )
        raise ActionNotAllowedError(error_message.format(algorithm.algorithm_id))
