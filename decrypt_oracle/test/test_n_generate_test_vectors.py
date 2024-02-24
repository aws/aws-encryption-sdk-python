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
"""Generate test vectors for use in testing the decrypt oracle."""
import base64
import binascii
import json
import os

import pytest
from aws_encryption_sdk_decrypt_oracle.key_providers.counting import CountingMasterKey
from aws_encryption_sdk_decrypt_oracle.key_providers.null import NullMasterKey
from typing import Dict, Iterable, Text

import aws_encryption_sdk
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.key_providers.kms import KMSMasterKey

from .integration.integration_test_utils import test_vectors_filename

HERE = os.path.abspath(os.path.dirname(__file__))
GENERATE_VECTORS = "AWS_ENCRYPTION_SDK_PYTHON_DECRYPT_ORACLE_GENERATE_TEST_VECTORS"
PUBLIC_CMK = "arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt"
ENCRYPTION_CONTEXT = {"key1": "val1", "key2": "val2"}


def _key_providers() -> Iterable[MasterKeyProvider]:
    """Generate all master key providers for test vector generation.
    Each will be used independently.
    """
    yield NullMasterKey()
    yield CountingMasterKey()
    yield KMSMasterKey(key_id=PUBLIC_CMK)


def _generate_vectors(key_provider: MasterKeyProvider, plaintext: bytes) -> Iterable[Dict[Text, Text]]:
    """Generate all desired test vectors for a given key provider and plaintext."""
    for algorithm_suite in aws_encryption_sdk.Algorithm:
        ciphertext, _header = aws_encryption_sdk.encrypt(
            source=plaintext,
            encryption_context=ENCRYPTION_CONTEXT,
            key_provider=key_provider,
            algorithm=algorithm_suite,
        )
        yield {
            "key-type": key_provider.provider_id,
            "algorithm-suite": binascii.hexlify(algorithm_suite.id_as_bytes()).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "plaintext": base64.b64encode(plaintext).decode("utf-8"),
        }


@pytest.mark.generate
@pytest.mark.skipif(GENERATE_VECTORS not in os.environ, reason="Generating test vectors is a rare occurance.")
def test_not_a_test_generate_test_vectors():
    """Generate all expected test vectors and write them to ``test/vectors/decrypt_oracle.json``."""
    vectors = []
    plaintext = os.urandom(64)
    for key_provider in _key_providers():
        vectors.extend(_generate_vectors(key_provider, plaintext))

    with open(test_vectors_filename(), "w") as output:
        json.dump(vectors, output, indent=4)
