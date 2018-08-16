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
"""Test suite for aws_encryption_sdk.materials_managers.base"""
import pytest

from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_abstracts():
    with pytest.raises(TypeError) as excinfo:
        CryptoMaterialsManager()

    excinfo.match(
        r"Can't instantiate abstract class CryptoMaterialsManager with abstract methods {}".format(
            ", ".join(["decrypt_materials", "get_encryption_materials"])
        )
    )
