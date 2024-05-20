# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit testing suite for commitment utility functions"""
import pytest
from mock import MagicMock

from aws_encryption_sdk.exceptions import ActionNotAllowedError
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy
from aws_encryption_sdk.internal.utils.commitment import (
    TROUBLESHOOTING_URL,
    validate_commitment_policy_on_decrypt,
    validate_commitment_policy_on_encrypt,
)

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


@pytest.mark.parametrize(
    "policy", (CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
)
def test_on_encrypt_committing_algorithm_policy_requires(policy):
    """Checks that validate_commitment_policy_on_encrypt with a committing algorithm and a policy that requires
    commitment succeeds."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = True

    validate_commitment_policy_on_encrypt(policy, algorithm)


def test_on_encrypt_uncommitting_algorithm_policy_allows():
    """Checks that validate_commitment_policy_on_encrypt with an uncommitting algorithm and a policy that does not
    require commitment succeeds."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = False

    validate_commitment_policy_on_encrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, algorithm)


@pytest.mark.parametrize(
    "policy", (CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
)
def test_on_encrypt_uncommitting_algorithm_policy_forbids(policy):
    """Checks that validate_commitment_policy_on_encrypt with an uncommitting algorithm and a policy that requires
    commitment fails."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = False

    with pytest.raises(ActionNotAllowedError) as excinfo:
        validate_commitment_policy_on_encrypt(policy, algorithm)
    excinfo.match(
        "Configuration conflict. Cannot encrypt due to .* requiring only committed messages. Algorithm ID was .*. "
        "See: " + TROUBLESHOOTING_URL
    )


@pytest.mark.parametrize(
    "policy",
    (
        CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
    ),
)
def test_on_decrypt_committing_algorithm_policy_allows(policy):
    """Checks that validate_commitment_policy_on_decrypt with a committing algorithm and a policy that allows
    commitment fails."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = True

    validate_commitment_policy_on_decrypt(policy, algorithm)


@pytest.mark.parametrize(
    "policy", (CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT, CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
)
def test_on_decrypt_uncommitting_algorithm_policy_allows(policy):
    """Checks that validate_commitment_policy_on_decrypt with an uncommitting algorithm and a policy that allows
    non-commitment fails."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = False

    validate_commitment_policy_on_decrypt(policy, algorithm)


def test_on_decrypt_uncommitting_algorithm_policy_requires():
    """Checks that validate_commitment_policy_on_decrypt with an uncommitting algorithm and a policy that requires
    commitment fails."""
    algorithm = MagicMock(__class__=Algorithm)
    algorithm.is_committing.return_value = False

    with pytest.raises(ActionNotAllowedError) as excinfo:
        validate_commitment_policy_on_decrypt(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, algorithm)
    excinfo.match(
        "Configuration conflict. Cannot decrypt due to .* requiring only committed messages. Algorithm ID was .*. "
        "See: " + TROUBLESHOOTING_URL
    )
