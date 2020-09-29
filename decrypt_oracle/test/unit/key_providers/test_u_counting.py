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
"""Unit test for ``aws_encryption_sdk_decrypt_oracle.key_providers.counting``."""
import aws_encryption_sdk
import pytest
from aws_encryption_sdk_decrypt_oracle.key_providers.counting import CountingMasterKey

from aws_encryption_sdk.identifiers import CommitmentPolicy
from ...integration.integration_test_utils import filtered_test_vectors

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize("vector", filtered_test_vectors(lambda x: x.key_type == "test_counting"))
def test_counting_master_key_decrypt_vectors(vector):
    master_key = CountingMasterKey()
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
    plaintext, _header = client.decrypt(source=vector.ciphertext, key_provider=master_key)

    assert plaintext == vector.plaintext


def test_counting_master_key_cycle():
    plaintext = b"some super secret plaintext"
    master_key = CountingMasterKey()

    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)

    ciphertext, _header = client.encrypt(source=plaintext, key_provider=master_key)
    decrypted, _header = client.decrypt(source=ciphertext, key_provider=master_key)

    assert plaintext != ciphertext
    assert plaintext == decrypted
