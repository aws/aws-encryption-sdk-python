# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Integration test utilities.
"""
import os

import pytest


def vectors_dir():
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, "..", "aws-crypto-tools-test-vector-framework"))


@pytest.fixture
def full_message_encrypt_vectors():
    return os.path.join(
        vectors_dir(), "features", "CANONICAL-GENERATED-MANIFESTS", "0003-awses-message-encryption.v2.json"
    )


@pytest.fixture
def full_message_decrypt_generation_vectors():
    return os.path.join(
        vectors_dir(), "features", "CANONICAL-GENERATED-MANIFESTS", "0006-awses-message-decryption-generation.v2.json"
    )
