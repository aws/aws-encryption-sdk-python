# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Command to generate AWS Encryption SDK full message decryption vectors."""
import argparse

from awses_test_vectors.manifests.full_message.decrypt_generation import MessageDecryptionGenerationManifest

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable, Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def cli(args=None):
    # type: (Optional[Iterable[str]]) -> None
    """CLI entry point for generating AWS Encryption SDK Decrypt Message manifests."""
    parser = argparse.ArgumentParser(description="Build a decrypt manifest from keys and decrypt generation manifests")
    parser.add_argument("--output", required=True, help="Directory in which to store results")
    parser.add_argument(
        "--input", required=True, type=argparse.FileType("r"), help="Existing full message decrypt generation manifest"
    )
    parser.add_argument(
        "--human",
        required=False,
        default=None,
        action="store_const",
        const=4,
        dest="json_indent",
        help="Output human-readable JSON",
    )

    parsed = parser.parse_args(args)

    encrypt_manifest = MessageDecryptionGenerationManifest.from_file(parsed.input)

    encrypt_manifest.run_and_write_to_dir(target_directory=parsed.output, json_indent=parsed.json_indent)
