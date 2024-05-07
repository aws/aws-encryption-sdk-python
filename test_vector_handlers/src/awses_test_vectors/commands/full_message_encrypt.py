# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Command to test AWS Encryption SDK full message encryption vectors."""
import argparse

from awses_test_vectors.manifests.full_message.encrypt import MessageEncryptionManifest

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable, Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def cli(args=None):
    # type: (Optional[Iterable[str]]) -> None
    """CLI entry point for processing AWS Encryption SDK Encrypt Message manifests."""
    parser = argparse.ArgumentParser(description="Build ciphertexts from keys and encrypt manifests")
    parser.add_argument(
        "--input", required=True, type=argparse.FileType("r"), help="Existing full message encrypt manifest"
    )

    parsed = parser.parse_args(args)

    encrypt_manifest = MessageEncryptionManifest.from_file(parsed.input)

    encrypt_manifest.run()
