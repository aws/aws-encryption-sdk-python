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
Integration tests for ``awses_test_vectors.commands.full_message_encrypt``.
"""
import pytest

from awses_test_vectors.commands import full_message_decrypt, full_message_encrypt

from ..integration_test_utils import full_message_encrypt_vectors  # noqa pylint: disable=unused-import

pytestmark = [pytest.mark.integ]


def test_full_message_encrypt_canonical_full(tmpdir, full_message_encrypt_vectors):
    output_dir = str(tmpdir.join("output"))
    full_message_encrypt.cli(["--output", output_dir, "--encrypt", full_message_encrypt_vectors])


def test_full_message_cycle_canonical_full(tmpdir, full_message_encrypt_vectors):
    output_dir = tmpdir.join("output")
    full_message_encrypt.cli(["--output", str(output_dir), "--encrypt", full_message_encrypt_vectors])

    decrypt_manifest_file = output_dir.join("decrypt_message.json")
    full_message_decrypt.cli(["--decrypt", str(decrypt_manifest_file)])
