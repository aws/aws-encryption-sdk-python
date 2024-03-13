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
Integration test utilities.
"""
import os

import pytest


here = os.path.abspath(os.path.dirname(__file__))


def legacy_vectors_dir():
    return os.path.abspath(os.path.join(here, "..", "aws-crypto-tools-test-vector-framework"))


def mpl_vectors_dir():
    return os.path.abspath(os.path.join(here, "..", "golden-manifest-TODORENAMEANDGETFROMGHA"))


def required_ec_vectors_dir():
    return os.path.abspath(os.path.join(here, "..", "required-ec-TODORENAMEANDGETFROMGHA"))


@pytest.fixture
def full_message_encrypt_vectors():
    return os.path.join(
        legacy_vectors_dir(), "features", "CANONICAL-GENERATED-MANIFESTS", "0003-awses-message-encryption.v2.json"
    )


@pytest.fixture
def full_message_decrypt_generation_vectors():
    return os.path.join(
        legacy_vectors_dir(), "features", "CANONICAL-GENERATED-MANIFESTS", "0006-awses-message-decryption-generation.v2.json"
    )


@pytest.fixture
def mpl_decrypt_vectors():
    return os.path.join(
        mpl_vectors_dir(), "manifest.json"
    )


@pytest.fixture
def required_encryption_context_cmm_decrypt_vectors():
    return os.path.join(
        required_ec_vectors_dir(), "manifest.json"
    )