# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test for ``aws_encryption_sdk_decrypt_oracle.key_providers.counting``."""
import pytest
from aws_encryption_sdk_decrypt_oracle.key_providers.counting import CountingMasterKey

from ...integration.integration_test_utils import CLIENT, filtered_test_vectors

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize("vector", filtered_test_vectors(lambda x: x.key_type == "test_counting"))
def test_counting_master_key_decrypt_vectors(vector):
    master_key = CountingMasterKey()

    plaintext, _header = CLIENT.decrypt(source=vector.ciphertext, key_provider=master_key)

    assert plaintext == vector.plaintext


def test_counting_master_key_cycle():
    plaintext = b"some super secret plaintext"
    master_key = CountingMasterKey()

    ciphertext, _header = CLIENT.encrypt(source=plaintext, key_provider=master_key)
    decrypted, _header = CLIENT.decrypt(source=ciphertext, key_provider=master_key)

    assert plaintext != ciphertext
    assert plaintext == decrypted
