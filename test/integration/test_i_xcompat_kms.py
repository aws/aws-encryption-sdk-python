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
"""Integration test suite testing decryption of known good test files encrypted using KMSMasterKeyProvider."""
import json
import os

import pytest

import aws_encryption_sdk

from .integration_test_utils import setup_kms_master_key_provider, skip_tests, SKIP_MESSAGE


# Environment-specific test file locator.  May not always exist.
def _file_root():
    return '.'


try:
    from .aws_test_file_finder import file_root
except ImportError:
    file_root = _file_root


def _generate_test_cases():
    if skip_tests():
        return []

    kms_key_provider = setup_kms_master_key_provider()
    try:
        root_dir = os.path.abspath(file_root())
    except Exception:  # pylint: disable=broad-except
        root_dir = os.getcwd()
    if not os.path.isdir(root_dir):
        root_dir = os.getcwd()
    base_dir = os.path.join(
        root_dir,
        'aws_encryption_sdk_resources'
    )
    ciphertext_manifest_path = os.path.join(
        base_dir,
        'manifests',
        'ciphertext.manifest'
    )

    if not os.path.isfile(ciphertext_manifest_path):
        # Make no test cases if the ciphertext file is not found
        return []

    with open(ciphertext_manifest_path) as f:
        ciphertext_manifest = json.load(f)
    _test_cases = []

    # Collect test cases from ciphertext manifest
    for test_case in ciphertext_manifest['test_cases']:
        for key in test_case['master_keys']:
            if key['provider_id'] == 'aws-kms' and key['decryptable']:
                _test_cases.append((
                    os.path.join(base_dir, test_case['plaintext']['filename']),
                    os.path.join(base_dir, test_case['ciphertext']['filename']),
                    kms_key_provider
                ))
                break
    return _test_cases


@pytest.mark.skipif(skip_tests(), reason=SKIP_MESSAGE)
@pytest.mark.parametrize('plaintext_filename,ciphertext_filename,key_provider', _generate_test_cases())
def test_decrypt_from_file(plaintext_filename, ciphertext_filename, key_provider):
    """Tests decrypt from known good files."""
    with open(ciphertext_filename, 'rb') as infile:
        ciphertext = infile.read()
    with open(plaintext_filename, 'rb') as infile:
        plaintext = infile.read()
    decrypted_ciphertext, _header = aws_encryption_sdk.decrypt(
        source=ciphertext,
        key_provider=key_provider
    )
    assert decrypted_ciphertext == plaintext
