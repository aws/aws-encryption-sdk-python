# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""
Integration tests for `awses_test_vectors.commands` with keyrings.
"""
import pytest

from awses_test_vectors.commands import full_message_decrypt, full_message_decrypt_generate, full_message_encrypt

from ....integration.integration_test_utils import (  # noqa pylint: disable=unused-import
    full_message_decrypt_generation_vectors,
    full_message_encrypt_vectors,
)

pytestmark = [pytest.mark.integ]


def test_full_message_encrypt_canonical_full(full_message_encrypt_vectors):
    full_message_encrypt.cli(["--input", full_message_encrypt_vectors])
    full_message_encrypt.cli(["--input", full_message_encrypt_vectors], "--keyrings")


def test_full_message_cycle_canonical_full(tmpdir, full_message_decrypt_generation_vectors):
    # Generate vectors using keyring interfaces
    keyring_output_dir = tmpdir.join("output-keyrings")
    full_message_decrypt_generate.cli([
        "--output",
        str(keyring_output_dir),
        "--input",
        full_message_decrypt_generation_vectors,
        "--keyrings"
    ])
    # Generate vectors using master key interfaces
    master_key_output_dir = tmpdir.join("output-master-key")
    full_message_decrypt_generate.cli([
        "--output",
        str(master_key_output_dir),
        "--input",
        full_message_decrypt_generation_vectors
    ])

    # Validate that vectors generated using keyring interfaces
    # can be decrypted by BOTH keyring and master key interfaces
    keyring_decrypt_manifest_file = keyring_output_dir.join("manifest.json")
    full_message_decrypt.cli(["--input", str(keyring_decrypt_manifest_file), "--keyrings"])
    full_message_decrypt.cli(["--input", str(keyring_decrypt_manifest_file)])

    # Validate that vectors generated using master key interfaces
    # can be decrypted by BOTH keyring and master key interfaces
    master_key_decrypt_manifest_file = keyring_output_dir.join("manifest.json")
    full_message_decrypt.cli(["--input", str(master_key_decrypt_manifest_file), "--keyrings"])
    full_message_decrypt.cli(["--input", str(master_key_decrypt_manifest_file)])
