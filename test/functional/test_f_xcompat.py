# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional test suite testing decryption of known good test files encrypted using static RawMasterKeyProvider."""
import base64
import json
import logging
import os
import sys
from collections import defaultdict

import attr
import pytest
import six

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import InvalidKeyIdError
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

pytestmark = [pytest.mark.accept]


# Environment-specific test file locator.  May not always exist.
def _file_root():
    return "."


try:
    from .aws_test_file_finder import file_root
except ImportError:
    file_root = _file_root

_LOGGER = logging.getLogger()


_WRAPPING_ALGORITHM_MAP = {
    b"AES": {
        128: {b"": {b"": WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING}},
        192: {b"": {b"": WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING}},
        256: {b"": {b"": WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING}},
    },
    b"RSA": defaultdict(
        lambda: {
            b"PKCS1": {b"": WrappingAlgorithm.RSA_PKCS1},
            b"OAEP-MGF1": {
                b"SHA-1": WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
                b"SHA-256": WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
                b"SHA-384": WrappingAlgorithm.RSA_OAEP_SHA384_MGF1,
                b"SHA-512": WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
            },
        }
    ),
}
_KEY_TYPES_MAP = {b"AES": EncryptionKeyType.SYMMETRIC, b"RSA": EncryptionKeyType.PRIVATE}
_STATIC_KEYS = defaultdict(dict)


class StaticStoredMasterKeyProvider(RawMasterKeyProvider):
    """Provides static key"""

    provider_id = "static-aws-xcompat"

    def _get_raw_key(self, key_id):
        """Finds a loaded raw key."""
        try:
            algorithm, key_bits, padding_algorithm, padding_hash = key_id.upper().split(b".", 3)
            key_bits = int(key_bits)
            key_type = _KEY_TYPES_MAP[algorithm]
            wrapping_algorithm = _WRAPPING_ALGORITHM_MAP[algorithm][key_bits][padding_algorithm][padding_hash]
            static_key = _STATIC_KEYS[algorithm][key_bits]
            return WrappingKey(
                wrapping_algorithm=wrapping_algorithm, wrapping_key=static_key, wrapping_key_type=key_type
            )
        except KeyError:
            _LOGGER.exception("Unknown Key ID: %s", key_id)
            raise InvalidKeyIdError("Unknown Key ID: {}".format(key_id))


@attr.s
class RawKeyDescription(object):
    """Customer raw key descriptor used by StaticStoredMasterKeyProvider."""

    encryption_algorithm = attr.ib(validator=attr.validators.instance_of(six.string_types))
    key_bits = attr.ib(validator=attr.validators.instance_of(int))
    padding_algorithm = attr.ib(validator=attr.validators.instance_of(six.string_types))
    padding_hash = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @property
    def key_id(self):
        """Build a key ID from instance parameters."""
        return ".".join([self.encryption_algorithm, str(self.key_bits), self.padding_algorithm, self.padding_hash])


@attr.s
class Scenario(object):
    """Scenario details."""

    plaintext_filename = attr.ib(validator=attr.validators.instance_of(six.string_types))
    ciphertext_filename = attr.ib(validator=attr.validators.instance_of(six.string_types))
    key_ids = attr.ib(validator=attr.validators.instance_of(list))


def _generate_test_cases():  # noqa=C901
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

    # Collect keys from ciphertext manifest
    for algorithm, keys in ciphertext_manifest["test_keys"].items():
        algorithm = to_bytes(algorithm.upper())
        for key_bits, key_desc in keys.items():
            key_desc = to_bytes(key_desc)
            key_bits = int(key_bits)
            raw_key = to_bytes(key_desc.get("line_separator", "").join(key_desc["key"]))
            if key_desc["encoding"].lower() in ("raw", "pem"):
                _STATIC_KEYS[algorithm][key_bits] = raw_key
            elif key_desc["encoding"].lower() == "base64":
                _STATIC_KEYS[algorithm][key_bits] = base64.b64decode(raw_key)
            else:
                raise Exception("TODO" + "Unknown key encoding")

    # Collect test cases from ciphertext manifest
    for test_case in ciphertext_manifest["test_cases"]:
        key_ids = []
        algorithm = aws_encryption_sdk.Algorithm.get_by_id(int(test_case["algorithm"], 16))
        for key in test_case["master_keys"]:
            sys.stderr.write("XC:: " + json.dumps(key) + "\n")
            if key["provider_id"] == StaticStoredMasterKeyProvider.provider_id:
                key_ids.append(
                    RawKeyDescription(
                        key["encryption_algorithm"],
                        key.get("key_bits", algorithm.data_key_len * 8),
                        key.get("padding_algorithm", ""),
                        key.get("padding_hash", ""),
                    ).key_id
                )
        if key_ids:
            _test_cases.append(
                Scenario(
                    os.path.join(base_dir, test_case["plaintext"]["filename"]),
                    os.path.join(base_dir, test_case["ciphertext"]["filename"]),
                    key_ids,
                )
            )
    return _test_cases


@pytest.mark.parametrize("scenario", _generate_test_cases())
def test_decrypt_from_file(scenario):
    """Tests decrypt from known good files."""
    with open(scenario.ciphertext_filename, "rb") as infile:
        ciphertext = infile.read()
    with open(scenario.plaintext_filename, "rb") as infile:
        plaintext = infile.read()
    key_provider = StaticStoredMasterKeyProvider()
    key_provider.add_master_keys_from_list(scenario.key_ids)
    decrypted_ciphertext, _header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=key_provider)
    assert decrypted_ciphertext == plaintext
