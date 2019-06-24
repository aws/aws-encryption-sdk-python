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
"""Resources required for Multi Keyrings."""
import attr
from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, RawRSAKeyring


@attr.s
class MultiKeyring(Keyring):
    generator = attr.ib(validator=attr.validators.instance_of(Keyring))
    children = attr.ib(validator=attr.validators.instance_of(list))

    def on_encrypt(self, encryption_materials):
        
        return encryption_materials

    def on_decrypt(self, decryption_materials):
        return decryption_materials
