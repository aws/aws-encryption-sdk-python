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

from awses_test_vectors.internal.aws_kms import arn_from_key_id
from awses_test_vectors.internal.defaults import ENCODING
from awses_test_vectors.internal.util import (
    dictionary_validator,
    iterable_validator,
    membership_validator,
    validate_manifest_type,
)

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import cast, Dict, Iterable, Optional  # noqa pylint: disable=unused-import
    from awses_test_vectors.internal.mypy_types import (  # noqa pylint: disable=unused-import
        AWS_KMS_KEY_SPEC,
        MANUAL_KEY_SPEC,
        KEY_SPEC,
        KEYS_MANIFEST,
    MANIFEST_VERSION
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

SUPPORTED_VERSIONS = (1,)
KEY_TYPES = ("symmetric", "private", "public")
KEY_ENCODINGS = ("base64", "pem")
KEY_ALGORITHMS = ("aes", "rsa")


@attr.s(init=False)
class KeySpec(object):
    """Base key specification.

    :param bool encrypt: Key can be used to encrypt
    :param bool decrypt: Key can be used to decrypt
    """

    # pylint: disable=too-few-public-methods

    encrypt = attr.ib(validator=attr.validators.instance_of(bool))
    decrypt = attr.ib(validator=attr.validators.instance_of(bool))

    def __init__(self, encrypt, decrypt):  # noqa=D107
        # type: (bool, bool) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.encrypt = encrypt
        self.decrypt = decrypt
        attr.validate(self)


@attr.s(init=False)
class AwsKmsKeySpec(KeySpec):
    """AWS KMS key specification.

    :param bool encrypt: Key can be used to encrypt
    :param bool decrypt: Key can be used to decrypt
    :param str type_name: Master key type name (must be "aws-kms")
    :param str key_id: Master key ID
    """

    # pylint: disable=too-few-public-methods

    type_name = attr.ib(validator=membership_validator(("aws-kms",)))
    key_id = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __init__(self, encrypt, decrypt, type_name, key_id):  # noqa=D107
        # type: (bool, bool, str, str) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.type_name = type_name
        self.key_id = key_id
        super(AwsKmsKeySpec, self).__init__(encrypt, decrypt)

    @property
    def manifest_spec(self):
        # type: () -> AWS_KMS_KEY_SPEC
        """Build a key specification describing this key specification.

        :return: Key specification JSON
        :rtype: dict
        """
        return {
            "encrypt": self.encrypt,
            "decrypt": self.decrypt,
            "type": self.type_name,
            "key-id": arn_from_key_id(self.key_id),
        }


@attr.s(init=False)
class ManualKeySpec(KeySpec):
    """Manual key specification.

    Allowed values described in AWS Crypto Tools Test Vector Framework feature #0002 Keys Manifest.

    :param bool encrypt: Key can be used to encrypt
    :param bool decrypt: Key can be used to decrypt
    :param str algorithm: Algorithm to use with key
    :param str type_name: Key type
    :param int bits: Key length in bits
    :param str encoding: Encoding used to encode key material
    :param material: Raw material encoded, then split into lines separated by ``line_separator``
    :type material: list of str
    :param str line_separator: Character with which to separate members of ``material``
        before decoding (optional: default is empty string)
    """

    algorithm = attr.ib(validator=membership_validator(KEY_ALGORITHMS))
    type_name = attr.ib(validator=membership_validator(KEY_TYPES))
    bits = attr.ib(validator=attr.validators.instance_of(int))
    encoding = attr.ib(validator=membership_validator(KEY_ENCODINGS))
    material = attr.ib(validator=iterable_validator(list, six.string_types))
    line_separator = attr.ib(default="", validator=attr.validators.instance_of(six.string_types))

    def __init__(
            self,
            encrypt,  # type: bool
            decrypt,  # type: bool
            algorithm,  # type: str
            type_name,  # type: str
            bits,  # type: int
            encoding,  # type: str
            material,  # type: Iterable[str]
            line_separator=''  # type: Optional[str]
    ):  # noqa=D107
        # type: (...) -> None
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.algorithm = algorithm
        self.type_name = type_name
        self.bits = bits
        self.encoding = encoding
        self.material = material
        self.line_separator = line_separator
        super(ManualKeySpec, self).__init__(encrypt, decrypt)

    @property
    def raw_material(self):
        # type: () -> bytes
        """Provide the raw binary material for this key.

        :return: Binary key material
        :rtype: bytes
        """
        raw_material = self.line_separator.join(self.material).encode(ENCODING)
        if self.encoding == "base64":
            return base64.b64decode(raw_material)

        return raw_material

    @property
    def manifest_spec(self):
        # type: () -> MANUAL_KEY_SPEC
        """Build a key specification describing this key specification.

        :return: Key specification JSON
        :rtype: dict
        """
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
    """Load a key from a key specification.

    :param dict key_spec: Key specification JSON
    :return: Loaded key
    :rtype: KeySpec
    """
    decrypt = key_spec['decrypt']  # type: bool
    encrypt = key_spec['encrypt']  # type: bool
    type_name = key_spec['type']  # type: str
    if key_spec["type"] == "aws-kms":
        key_id = key_spec['key-id']  # type: str
        return AwsKmsKeySpec(
            encrypt=encrypt,
            decrypt=decrypt,
            type_name=type_name,
            key_id=key_id,
        )

    algorithm = key_spec['algorithm']  # type: str
    bits = key_spec['bits']  # type: int
    encoding = key_spec['encoding']  # type: str
    line_separator = key_spec.get('line-separator', '')  # type: str
    material = key_spec['material']  # type: Iterable[str]
    return ManualKeySpec(
        encrypt=encrypt,
        decrypt=decrypt,
        type_name=type_name,
        algorithm=algorithm,
        bits=bits,
        encoding=encoding,
        line_separator=line_separator,
        material=material,
    )


@attr.s
class KeysManifest(object):
    """Keys Manifest handler.

    Described in AWS Crypto Tools Test Vector Framework feature #0002 Keys Manifest.

    :param int version: Version of this manifest
    :param dict keys: Mapping of key names to :class:`KeySpec`s
    """

    version = attr.ib(validator=membership_validator(SUPPORTED_VERSIONS))
    keys = attr.ib(validator=dictionary_validator(six.string_types, KeySpec))
    type_name = "keys"

    @classmethod
    def from_manifest_spec(cls, raw_manifest):
        # type: (KEYS_MANIFEST) -> KeysManifest
        """"""
        manifest_version = raw_manifest["manifest"]  # type: MANIFEST_VERSION
        validate_manifest_type(
            type_name=cls.type_name, manifest_version=manifest_version, supported_versions=SUPPORTED_VERSIONS
        )
        raw_key_specs = raw_manifest["keys"]  # type: Dict[str, KEY_SPEC]
        keys = {name: key_from_manifest_spec(key_spec) for name, key_spec in raw_key_specs.items()}
        return cls(version=raw_manifest["manifest"]["version"], keys=keys)

    def key(self, name):
        # type: (str) -> KeySpec
        """Provide the key with the specified name.

        :param str name: Key name
        :return: Specified key
        :rtype: KeySpec
        :raises ValueError: if key name is unknown
        """
        try:
            return self.keys[name]
        except KeyError:
            raise ValueError('Unknown key name: "{}"'.format(name))

    @property
    def manifest_spec(self):
        # type: () -> KEYS_MANIFEST
        """Build a keys manifest describing this manifest.

        :return: Manifest JSON
        :rtype: dict
        """
        return {
            "manifest": {"type": self.type_name, "version": self.version},
            "keys": {name: key.manifest_spec for name, key in self.keys.items()},
        }
