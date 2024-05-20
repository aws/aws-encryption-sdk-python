# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration test suite testing decryption of known good test files encrypted using KMSMasterKeyProvider."""
import json
import os

import pytest

import aws_encryption_sdk

from .integration_test_utils import setup_kms_master_key_provider

pytestmark = [pytest.mark.accept]


# Environment-specific test file locator.  May not always exist.
def _file_root():
    return "."


try:
    from .aws_test_file_finder import file_root
except ImportError:
    file_root = _file_root


def _generate_test_cases():
    try:
        root_dir = os.path.abspath(file_root())
    except Exception:  # pylint: disable=broad-except
        root_dir = os.getcwd()
    if not os.path.isdir(root_dir):
        root_dir = os.getcwd()
    base_dir = os.path.join(root_dir, "aws_encryption_sdk_resources")
    ciphertext_manifest_path = os.path.join(base_dir, "manifests", "ciphertext.manifest")

    if not os.path.isfile(ciphertext_manifest_path):
        # Make no test cases if the ciphertext file is not found
        return []

    with open(ciphertext_manifest_path, encoding="utf-8") as f:
        ciphertext_manifest = json.load(f)
    _test_cases = []

    # Collect test cases from ciphertext manifest
    for test_case in ciphertext_manifest["test_cases"]:
        for key in test_case["master_keys"]:
            if key["provider_id"] == "aws-kms" and key["decryptable"]:
                _test_cases.append(
                    (
                        os.path.join(base_dir, test_case["plaintext"]["filename"]),
                        os.path.join(base_dir, test_case["ciphertext"]["filename"]),
                    )
                )
                break
    return _test_cases


@pytest.mark.parametrize("plaintext_filename, ciphertext_filename", _generate_test_cases())
def test_decrypt_from_file(plaintext_filename, ciphertext_filename):
    """Tests decrypt from known good files."""
    with open(ciphertext_filename, "rb", encoding="utf-8") as infile:
        ciphertext = infile.read()
    with open(plaintext_filename, "rb", encoding="utf-8") as infile:
        plaintext = infile.read()
    decrypted_ciphertext, _header = aws_encryption_sdk.decrypt(
        source=ciphertext, key_provider=setup_kms_master_key_provider()
    )
    assert decrypted_ciphertext == plaintext
