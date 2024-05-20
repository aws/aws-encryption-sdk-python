# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for CryptoMaterialsCache"""
import pytest

from aws_encryption_sdk.caches.base import CryptoMaterialsCache

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_abstracts():
    with pytest.raises(TypeError, match='instantiate abstract class CryptoMaterialsCache') as excinfo:
        CryptoMaterialsCache()

    exception = str(excinfo.value)
    method_names = [
        "get_decryption_materials",
        "get_encryption_materials",
        "put_decryption_materials",
        "put_encryption_materials"
    ]
    for name in method_names:
        if exception.rfind(name) == -1:
            raise AssertionError("{} missing from Exception Message".format(name))
