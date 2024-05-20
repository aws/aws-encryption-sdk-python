# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for aws_encryption_sdk.materials_managers.base"""
import pytest

from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_abstracts():
    with pytest.raises(TypeError, match='instantiate abstract class CryptoMaterialsManager') as excinfo:
        CryptoMaterialsManager()
    method_names = ["decrypt_materials", "get_encryption_materials"]
    exception = str(excinfo.value)
    for name in method_names:
        if exception.rfind(name) == -1:
            raise AssertionError("{} missing from Exception Message".format(name))
