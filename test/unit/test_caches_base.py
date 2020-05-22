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
"""Unit test suite for CryptoMaterialsCache"""
import pytest

from aws_encryption_sdk.caches.base import CryptoMaterialsCache

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_abstracts():
    with pytest.raises(TypeError) as excinfo:
        CryptoMaterialsCache()

    excinfo.match(
        r"Can't instantiate abstract class CryptoMaterialsCache with abstract methods {}".format(
            ", ".join(
                [
                    "get_decryption_materials",
                    "get_encryption_materials",
                    "put_decryption_materials",
                    "put_encryption_materials",
                ]
            )
        )
    )
