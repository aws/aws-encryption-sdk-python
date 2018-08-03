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

Described in AWS Crypto Tools Test Vector Framework feature #0002 Keys Manifest.
"""
import base64

import attr
import six

from awses_test_vectors.util import (
    dictionary_validator,
    iterable_validator,
    membership_validator,
    validate_manifest_type,
)

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from awses_test_vectors.mypy_types import (  # noqa pylint: disable=unused-import
        AWS_KMS_KEY_SPEC,
        MANUAL_KEY_SPEC,
        KEY_SPEC,
        KEYS_MANIFEST,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

SUPPORTED_VERSIONS = (1,)
KEY_TYPES = ("symmetric", "private", "public")
KEY_ENCODINGS = ("base64", "pem")
KEY_ALGORITHMS = ("aes", "rsa")


@attr.s
class KeySpec(object):
    """"""

    # pylint: disable=too-few-public-methods

    encrypt = attr.ib(validator=attr.validators.instance_of(bool))
    decrypt = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s
class AwsKmsKeySpec(KeySpec):
    """"""

    # pylint: disable=too-few-public-methods

    type_name = attr.ib(validator=membership_validator(("aws-kms",)))
    key_id = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @property
    def manifest_spec(self):
        # type: () -> AWS_KMS_KEY_SPEC
        """"""
        return {"encrypt": self.encrypt, "decrypt": self.decrypt, "type": self.type_name, "key-id": self.key_id}


@attr.s
class ManualKeySpec(KeySpec):
    """"""

    algorithm = attr.ib(validator=membership_validator(KEY_ALGORITHMS))
    type_name = attr.ib(validator=membership_validator(KEY_TYPES))
    bits = attr.ib(validator=attr.validators.instance_of(int))
    encoding = attr.ib(validator=membership_validator(KEY_ENCODINGS))
    material = attr.ib(validator=iterable_validator(list, six.string_types))
    line_separator = attr.ib(default="", validator=attr.validators.instance_of(six.string_types))

    @property
    def raw_material(self):
        # type: () -> bytes
        """"""
        raw_material = self.line_separator.join(self.material).encode("utf-8")
        if self.encoding == "base64":
            return base64.b64decode(raw_material)

        return raw_material

    @property
    def manifest_spec(self):
        # type: () -> MANUAL_KEY_SPEC
        """"""
        return {
            "encrypt": self.encrypt,
            "decrypt": self.decrypt,
            "algorithm": self.algorithm,
            "type": self.type_name,
            "bits": self.bits,
            "encoding": self.encoding,
            "line-separator": self.line_separator,
            "material": self.material,
        }


def key_from_manifest_spec(key_spec):
    # type: (KEY_SPEC) -> KeySpec
    """"""
    if key_spec["type"] == "aws-kms":
        return AwsKmsKeySpec(
            encrypt=key_spec["encrypt"],
            decrypt=key_spec["decrypt"],
            type_name=key_spec["type"],
            key_id=key_spec["key-id"],
        )

    return ManualKeySpec(
        encrypt=key_spec["encrypt"],
        decrypt=key_spec["decrypt"],
        type_name=key_spec["type"],
        algorithm=key_spec["algorithm"],
        bits=key_spec["bits"],
        encoding=key_spec["encoding"],
        line_separator=key_spec.get("line-separator", ""),
        material=key_spec["material"],
    )


@attr.s
class KeysManifest(object):
    """"""

    version = attr.ib(validator=membership_validator(SUPPORTED_VERSIONS))
    keys = attr.ib(validator=dictionary_validator(six.string_types, KeySpec))
    type_name = "keys"

    @classmethod
    def from_manifest_spec(cls, raw_manifest):
        # type: (KEYS_MANIFEST) -> KeysManifest
        """"""
        validate_manifest_type(
            type_name=cls.type_name, manifest_version=raw_manifest["manifest"], supported_versions=SUPPORTED_VERSIONS
        )
        keys = {name: key_from_manifest_spec(key_spec) for name, key_spec in raw_manifest["keys"].items()}
        return cls(version=raw_manifest["manifest"]["version"], keys=keys)

    def key(self, name):
        # type: (str) -> KeySpec
        """"""
        try:
            return self.keys[name]
        except KeyError:
            raise ValueError('Unknown key name: "{}"'.format(name))

    @property
    def manifest_spec(self):
        # type: () -> KEYS_MANIFEST
        """"""
        return {
            "manifest": {"type": self.type_name, "version": self.version},
            "keys": {name: key.manifest_spec for name, key in self.keys.items()},
        }
