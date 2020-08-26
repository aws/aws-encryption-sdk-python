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
"""Unit testing suite for commitment utility functions"""
import pytest
from mock import MagicMock

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy
from aws_encryption_sdk.internal.utils.commitment import TROUBLESHOOTING_URL, validate_commitment_policy_on_encrypt

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_on_encrypt_committing_algorithm_policy_forbids():
    """Checks that validate_commitment_policy_on_encrypt with a committing algorithm and a policy that does not allow
    commitment fails."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = True

    with pytest.raises(ActionNotAllowedError) as excinfo:
        validate_commitment_policy_on_encrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, algorithm)
    excinfo.match(
        "Configuration conflict. Cannot encrypt due to .* requiring only non-committed messages. Algorithm ID was .*. "
        "See: " + TROUBLESHOOTING_URL
    )


def test_on_encrypt_uncommitting_algorithm_policy_allows():
    """Checks that validate_commitment_policy_on_encrypt with an uncommitting algorithm and a policy that does not
    require commitment succeeds."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = False

    validate_commitment_policy_on_encrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, algorithm)
