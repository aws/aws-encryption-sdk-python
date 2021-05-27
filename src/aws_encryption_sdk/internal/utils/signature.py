# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
