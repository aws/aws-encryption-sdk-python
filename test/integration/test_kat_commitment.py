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
"""Known answer test suite for functionality related to key commitment."""
import base64
import json
import os
import sys
from test.functional.test_f_commitment import StaticRawMasterKeyProvider

import pytest

import aws_encryption_sdk
from aws_encryption_sdk.exceptions import MasterKeyProviderError
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.key_providers.kms import DiscoveryAwsKmsMasterKeyProvider

pytestmark = [pytest.mark.integ]


FILE_NAME = "commitment-test-vectors.json"


# Environment-specific test file locator.  May not always exist.
def _file_root():
    return "."


try:
    from .aws_test_file_finder import file_root
except ImportError:
    file_root = _file_root


try:
    root_dir = os.path.abspath(file_root())
except Exception:  # pylint: disable=broad-except
    root_dir = os.getcwd()
if not os.path.isdir(root_dir):
    root_dir = os.getcwd()
base_dir = os.path.join(root_dir, "test", "resources")
file_path = os.path.join(base_dir, FILE_NAME)

test_str = open(file_path, "r").read()
test_json = json.loads(test_str)
kat_tests = test_json["tests"]


@pytest.mark.parametrize("info", kat_tests, ids=[info["comment"] for info in kat_tests])
def test_kat(info):
    """Tests known answer tests"""
    client = aws_encryption_sdk.EncryptionSDKClient()
    provider = None
    if info["keyring-type"] == "static":
        key_bytes = b"\00" * 32
        provider = StaticRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            encryption_key_type=EncryptionKeyType.SYMMETRIC,
            key_bytes=key_bytes,
        )
        provider.add_master_key("KeyId")
    else:
        provider = DiscoveryAwsKmsMasterKeyProvider()

    ciphertext = base64.b64decode(info["ciphertext"])

    if info["exception"]:
        with pytest.raises(MasterKeyProviderError) as excinfo:
            client.decrypt(source=ciphertext, key_provider=provider)
        expected_error = "Key commitment validation failed"
        excinfo.match(expected_error)
    else:
        plaintext, header = client.decrypt(source=ciphertext, key_provider=provider)

        # Only supporting single frame messages for now
        if sys.version_info[0] == 3:
            expected_plaintext = bytes("".join(info["plaintext-frames"]), "utf-8")
        else:
            expected_plaintext = bytes(str("".join(info["plaintext-frames"]).encode("utf-8")))
        assert expected_plaintext == plaintext

        expected_commitment = base64.b64decode(info["commitment"])
        assert expected_commitment == header.commitment_key

        expected_message_id = base64.b64decode(info["message-id"])
        assert expected_message_id == header.message_id

        expected_encryption_context = info["encryption-context"]
        assert expected_encryption_context == header.encryption_context
