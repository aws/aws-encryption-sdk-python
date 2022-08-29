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
        timeout=120  # 2 minutes
    )
    assert response.status_code == 200
    assert response.content == vector.plaintext
