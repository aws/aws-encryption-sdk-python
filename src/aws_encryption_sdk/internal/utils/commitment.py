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
