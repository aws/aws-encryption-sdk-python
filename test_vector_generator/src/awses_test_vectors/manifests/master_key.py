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
AWS Encryption SDK master key specification utilities.
"""
import base64

import attr
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKey
from aws_encryption_sdk.key_providers.kms import KMSMasterKey
from aws_encryption_sdk.key_providers.raw import RawMasterKey
import six

from awses_test_vectors.manifests.keys import KeysManifest, KeySpec
from awses_test_vectors.util import membership_validator

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Dict, Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

KNOWN_TYPES = ('aws-kms', 'raw')
KNOWN_ALGORITHMS = ('aes', 'rsa')
KNOWN_PADDING = ('pkcs1', 'oaep-mgf1')
KNOWN_PADDING_HASH = ('sha1', 'sha256', 'sha384', 'sha512')
_RAW_WRAPPING_KEY_ALGORITHMS = {
    'aes/128': WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
    'aes/192': WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
    'aes/256': WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    'rsa/pkcs1': WrappingAlgorithm.RSA_PKCS1,
    'rsa/oaep-mgf1/sha1': WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
    'rsa/oaep-mgf1/sha256': WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    # \/ not yet implemented \/
    #'rsa/oaep-mgf1/sha384': WrappingAlgorithm.RSA_OAEP_SHA384_MGF1,
    #'rsa/oaep-mgf1/sha512': WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
}
_RAW_ENCRYPTION_KEY_TYPE = {
    'symmetric': EncryptionKeyType.SYMMETRIC,
    'private': EncryptionKeyType.PRIVATE,
    'public': EncryptionKeyType.PUBLIC
}


@attr.s
class MasterKeySpec(object):
    """"""
    type_name = attr.ib(validator=membership_validator('master key type', _MASTER_KEY_LOADERS.keys()))
    key_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    key_id = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    provider_id = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    encryption_algorithm = attr.ib(
        validator=attr.validators.optional(membership_validator('encryption algorithm', KNOWN_ALGORITHMS))
    )
    padding_algorithm = attr.ib(
        validator=attr.validators.optional(membership_validator('padding algorithm', KNOWN_PADDING))
    )
    padding_hash = attr.ib(
        validator=attr.validators.optional(membership_validator('padding hash', KNOWN_PADDING_HASH))
    )

    def __attrs_post_init__(self):
        # type: () -> None
        """"""
        if self.type_name == 'aws-kms' and self.key_id is not None:
            raise ValueError('Key ID must be blank for AWS KMS master keys')

        if self.type_name == 'raw':
            if None in (self.provider_id, self.encryption_algorithm, self.padding_algorithm):
                raise ValueError(
                    'Provider ID, encryption algorithm, and padding algorithm are all required for raw keys'
                )

            if self.padding_algorithm == 'oaep-mgf1' and self.padding_hash is None:
                raise ValueError('Padding hash must be specified if padding algorithm is "oaep-mgf1"')

    @classmethod
    def from_scenario_spec(cls, spec):
        # type: (Dict[str, Any]) -> MasterKeySpec
        """"""
        return cls(
            type_name=spec['type'],
            key_name=spec['key'],
            key_id=spec.get('key-id'),
            provider_id=spec.get('provider-id'),
            encryption_algorithm=spec.get('encryption-algorithm'),
            padding_algorithm=spec.get('padding-algorithm'),
            padding_hash=spec.get('padding-hash')
        )

    def _wrapping_algorithm(self, key_bits):
        # type: (int) -> WrappingAlgorithm
        """"""
        key_spec_values = [self.encryption_algorithm]
        if self.encryption_algorithm == 'aes':
            key_spec_values.append(str(key_bits))

        elif self.encryption_algorithm == 'rsa':
            key_spec_values.append(self.padding_algorithm)

            if self.padding_hash is not None:
                key_spec_values.append(self.padding_hash)

        return _RAW_WRAPPING_KEY_ALGORITHMS['/'.join(key_spec_values)]

    def _wrapping_key(self, key_spec):
        # type: (KeySpec) -> WrappingKey
        """"""
        algorithm = self._wrapping_algorithm(key_spec.bits)
        material = key_spec.raw_material
        key_type = _RAW_ENCRYPTION_KEY_TYPE[key_spec.type_name]
        return WrappingKey(
            wrapping_algorithm=algorithm,
            wrapping_key=material,
            wrapping_key_type=key_type
        )

    def _raw_key_id(self):
        # type: () -> str
        """"""
        return self.key_id if self.key_id is not None else self.key_name

    def _raw_master_key_from_spec(self, key_spec):
        # type: (KeySpec) -> MasterKey
        """"""
        wrapping_key = self._wrapping_key(key_spec)
        key_id = self._raw_key_id()
        return RawMasterKey(
            provider_id=self.provider_id,
            key_id=key_id,
            wrapping_key=wrapping_key
        )

    def _kms_master_key_from_spec(self, key_spec):
        # type: (KeySpec) -> MasterKey
        """"""
        return KMSMasterKey(key_ids=[key_spec.key_id])

    _MASTER_KEY_LOADERS = {'aws-kms': _kms_master_key_from_spec, 'raw': _raw_master_key_from_spec}

    def master_key(self, keys):
        # type: (KeysManifest) -> MasterKey
        """"""
        key_spec = keys.key(self.key_name)
        key_loader = self._MASTER_KEY_LOADERS[self.type_name]
        return key_loader(key_spec)
