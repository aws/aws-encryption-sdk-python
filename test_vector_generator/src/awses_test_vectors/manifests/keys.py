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
"""
Keys Manifest handler.
"""
import base64

import attr
from enum import Enum
import six

from awses_test_vectors.util import membership_validator, validate_manifest_type

SUPPORTED_VERSIONS = (1,)
KEY_TYPES = ('symmetric', 'private', 'public')
KEY_ENCODINGS = ('base64', 'pem')
KEY_ALGORITHMS = ('aes', 'rsa')


@attr.s
class KeySpec(object):
    """"""
    encrypt = attr.ib(validator=attr.validators.instance_of(bool))
    decrypt = attr.ib(validator=attr.validators.instance_of(bool))
    type_name = attr.ib(validator=attr.validators.instance_of(six.string_types))


@attr.s
class AwsKmsKeySpec(KeySpec):
    """"""
    key_type = attr.ib()
    key_id = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @key_type.validator
    def check_key_type(self, attribute, value):
        """"""
        if value != 'aws-kms':
            raise ValueError('Key type mismatch: "{actual}" != "aws-kms"'.format(actual=value))


@attr.s
class ManualKeySpec(KeySpec):
    """"""
    algorithm = attr.ib(validator=membership_validator('key algorithm', KEY_ALGORITHMS))
    key_type = attr.ib(validator=membership_validator('key type', KEY_TYPES))
    bits = attr.ib(validator=attr.validators.instance_of(int))
    encoding = attr.ib(validator=membership_validator('key encoding', KEY_ENCODINGS))
    material = attr.ib()
    line_separator = attr.ib(
        default='',
        validator=attr.validators.instance_of(six.string_types)
    )

    @material.validator
    def check_material(self, attribute, value):
        """"""
        if not isinstance(value, list):
            raise ValueError('key material must be a list')

        for line in value:
            if not isinstance(line, six.string_types):
                raise ValueError('all key material members must be strings')

    @property
    def raw_material(self):
        # type: () -> bytes
        """"""
        raw_material = self.line_separator.join(self.material).encode('utf-8')
        if self.encoding == 'base64':
            return base64.b64decode(raw_material)

        return raw_material


def key_from_manifest_spec(key_spec):
    # type: (Dict[str, Any]) -> KeySpec
    """"""
    if key_spec['type'] == 'aws-kms':
        return AwsKmsKeySpec(
            encrypt=key_spec['encrypt'],
            decrypt=key_spec['decrypt'],
            type_name=key_spec['type'],
            key_id=key_spec['key-id'],
        )

    return ManualKeySpec(
        encrypt=key_spec['encrypt'],
        decrypt=key_spec['decrypt'],
        type_name=key_spec['type'],
        algorithm=key_spec['algorithm'],
        key_type=key_spec['type'],
        bits=key_spec['bits'],
        encoding=key_spec['encoding'],
        line_separator=key_spec['line-separator'],
        material=key_spec['material'],
    )


class KeysManifest(object):
    """"""
    type_name = 'keys'

    @classmethod
    def from_raw_manifest(cls, raw_manifest):
        # type: (Dict[str, Any]) -> KeysManifest
        """"""
        validate_manifest_type(
            type_name=cls.type_name,
            manifest=raw_manifest,
            supported_versions=SUPPORTED_VERSIONS
        )
        instance = cls()
        instance.version = raw_manifest['manifest']['version']
        instance.keys = {
            name: key_from_manifest_spec(key_spec)
            for name, key_spec
            in raw_manifest['keys'].items()
        }
        return instance

    def key(self, name):
        # type: (str) -> KeySpec
        """"""
        try:
            return self.keys[name]
        except KeyError:
            raise ValueError('Unknown key name: "{}"'.format(name))
