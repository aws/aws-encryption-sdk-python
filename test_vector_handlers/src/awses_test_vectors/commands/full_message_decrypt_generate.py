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
    parser.add_argument(
        "--keyrings",
        action="store_true",
        required=False,
        default=False,
        help="Use keyring interfaces to encrypt",
    )

    parsed = parser.parse_args(args)

    encrypt_manifest = MessageDecryptionGenerationManifest.from_file(parsed.input, parsed.keyrings)

    encrypt_manifest.run_and_write_to_dir(target_directory=parsed.output, json_indent=parsed.json_indent)
