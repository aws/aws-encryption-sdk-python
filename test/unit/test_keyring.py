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
"""Test suite for ``aws_encryption_sdk.keyrings``"""
import pytest

from aws_encryption_sdk.keyrings import Keyring

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_interface_enforcement():
    class BrokenKeyring(Keyring):
        """This keyring does not implement the private interface."""

    with pytest.raises(TypeError) as excinfo:
        BrokenKeyring()

    excinfo.match("Can't instantiate abstract class BrokenKeyring with abstract methods _on_decrypt, _on_encrypt")
