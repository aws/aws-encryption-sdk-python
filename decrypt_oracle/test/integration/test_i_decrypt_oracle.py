# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for deployed API."""
import pytest
import requests

from .integration_test_utils import all_test_vectors, decrypt_endpoint

pytestmark = [pytest.mark.integ]


@pytest.mark.parametrize("vector", all_test_vectors())
def test_all_vectors(vector):
    response = requests.post(
        decrypt_endpoint(),
        data=vector.ciphertext,
        headers={"Content-Type": "application/octet-stream", "Accept": "application/octet-stream"},
    )
    assert response.status_code == 200
    assert response.content == vector.plaintext
