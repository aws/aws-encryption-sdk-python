# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Integration tests for ``awses_test_vectors.commands``.
"""
import pytest

from awses_test_vectors.commands import full_message_decrypt, full_message_decrypt_generate, full_message_encrypt

from ..integration_test_utils import (  # noqa pylint: disable=unused-import
    full_message_decrypt_generation_vectors,
    full_message_encrypt_vectors,
)

pytestmark = [pytest.mark.integ]


def test_full_message_encrypt_canonical_full(full_message_encrypt_vectors):
    full_message_encrypt.cli(["--input", full_message_encrypt_vectors])


def test_full_message_cycle_canonical_full(tmpdir, full_message_decrypt_generation_vectors):
    output_dir = tmpdir.join("output")
    full_message_decrypt_generate.cli(["--output", str(output_dir), "--input", full_message_decrypt_generation_vectors])

    decrypt_manifest_file = output_dir.join("manifest.json")
    full_message_decrypt.cli(["--input", str(decrypt_manifest_file)])
