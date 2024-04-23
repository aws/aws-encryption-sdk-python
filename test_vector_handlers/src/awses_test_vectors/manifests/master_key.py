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

Described in AWS Crypto Tools Test Vector Framework features #0003 and #0004.
"""
import attr
import six
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.key_providers.base import MasterKeyProvider  # noqa pylint: disable=unused-import
from aws_encryption_sdk.key_providers.kms import (  # noqa pylint: disable=unused-import
    DiscoveryFilter,
    KMSMasterKey,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
)
from aws_encryption_sdk.key_providers.raw import RawMasterKey

from awses_test_vectors.internal.aws_kms import KMS_MASTER_KEY_PROVIDER, KMS_MRK_AWARE_MASTER_KEY_PROVIDER
from awses_test_vectors.internal.util import membership_validator
from awses_test_vectors.manifests.keys import KeysManifest, KeySpec  # noqa pylint: disable=unused-import

try:
    from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
except ImportError:
    from aws_encryption_sdk.internal.crypto import WrappingKey


try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import

    from awses_test_vectors.internal.mypy_types import MASTER_KEY_SPEC  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

KNOWN_TYPES = ("aws-kms", "aws-kms-mrk-aware", "aws-kms-mrk-aware-discovery", "raw", "aws-kms-hierarchy")
KNOWN_ALGORITHMS = ("aes", "rsa")
KNOWN_PADDING = ("pkcs1", "oaep-mgf1")
KNOWN_PADDING_HASH = ("sha1", "sha256", "sha384", "sha512")
_RAW_WRAPPING_KEY_ALGORITHMS = {
    "aes/128": WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
    "aes/192": WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
    "aes/256": WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    "rsa/pkcs1": WrappingAlgorithm.RSA_PKCS1,
    "rsa/oaep-mgf1/sha1": WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
    "rsa/oaep-mgf1/sha256": WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
}
try:
    _RAW_WRAPPING_KEY_ALGORITHMS.update(
        {
            "rsa/oaep-mgf1/sha384": WrappingAlgorithm.RSA_OAEP_SHA384_MGF1,
            "rsa/oaep-mgf1/sha512": WrappingAlgorithm.RSA_OAEP_SHA512_MGF1,
        }
    )
    _NOT_YET_IMPLEMENTED = {}
except AttributeError:
    _NOT_YET_IMPLEMENTED = {"rsa/oaep-mgf1/sha384", "rsa/oaep-mgf1/sha512"}
_RAW_ENCRYPTION_KEY_TYPE = {
    "symmetric": EncryptionKeyType.SYMMETRIC,
    "private": EncryptionKeyType.PRIVATE,
    "public": EncryptionKeyType.PUBLIC,
}


@attr.s
class MasterKeySpec(object):  # pylint: disable=too-many-instance-attributes
    """AWS Encryption SDK master key specification utilities.

    Described in AWS Crypto Tools Test Vector Framework features #0003 and #0004.

    :param str type_name: Master key type name
    :param str key_name: Name of key in keys spec
    :param str provider_id: Master key provider ID
    :param str encryption_algorithm: Wrapping key encryption algorithm (required for raw master keys)
    :param str padding_algorithm: Wrapping key padding algorithm (required for raw master keys)
    :param str padding_hash: Wrapping key padding hash (required for raw master keys)
    """

    type_name = attr.ib(validator=membership_validator(KNOWN_TYPES))
    key_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    default_mrk_region = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    discovery_filter = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(DiscoveryFilter)))
    provider_id = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    encryption_algorithm = attr.ib(validator=attr.validators.optional(membership_validator(KNOWN_ALGORITHMS)))
    padding_algorithm = attr.ib(validator=attr.validators.optional(membership_validator(KNOWN_PADDING)))
    padding_hash = attr.ib(validator=attr.validators.optional(membership_validator(KNOWN_PADDING_HASH)))

    def __attrs_post_init__(self):
        # type: () -> None
        """Verify that known types all have loaders and that all required parameters are provided."""
        # if set(KNOWN_TYPES) != set(self._MASTER_KEY_LOADERS.keys()):
        #     raise NotImplementedError("Gap found between known master key types and available master key loaders.")

        if self.type_name == "raw":
            if None in (self.provider_id, self.encryption_algorithm):
                raise ValueError("Provider ID and encryption algorithm are both required for raw keys")

            if self.encryption_algorithm == "rsa" and self.padding_algorithm is None:
                raise ValueError("Padding algorithm is required for raw RSA keys")

            if self.padding_algorithm == "oaep-mgf1" and self.padding_hash is None:
                raise ValueError('Padding hash must be specified if padding algorithm is "oaep-mgf1"')

        if self.type_name == "aws-kms-mrk-aware-discovery":
            if self.default_mrk_region is None:
                raise ValueError("Default MRK region is required for MRK-aware discovery master keys")

    @classmethod
    def from_scenario(cls, spec):
        # type: (MASTER_KEY_SPEC) -> MasterKeySpec
        """Load from a master key specification.

        :param dict spec: Master key specification JSON
        :return: Loaded master key specification
        :rtype: MasterKeySpec
        """
        return cls(
            type_name=spec["type"],
            key_name=spec.get("key"),
            default_mrk_region=spec.get("default-mrk-region"),
            discovery_filter=cls._discovery_filter_from_spec(spec.get("aws-kms-discovery-filter")),
            provider_id=spec.get("provider-id"),
            encryption_algorithm=spec.get("encryption-algorithm"),
            padding_algorithm=spec.get("padding-algorithm"),
            padding_hash=spec.get("padding-hash"),
        )

    @classmethod
    def _discovery_filter_from_spec(cls, spec):
        if spec:
            return DiscoveryFilter(partition=str(spec["partition"]), account_ids=spec["account-ids"])
        return None

    @classmethod
    def _discovery_filter_spec(cls, discovery_filter):
        return {"partition": discovery_filter.partition, "account-ids": discovery_filter.account_ids}

    def _wrapping_algorithm(self, key_bits):
        # type: (int) -> WrappingAlgorithm
        """Determine the correct wrapping algorithm if this is a raw master key.

        :param key_bits: Key size in bits
        :return: Correct wrapping algorithm
        :rtype: WrappingAlgorithm
        :raises TypeError: if this is not a raw master key specification
        """
        if not self.type_name == "raw":
            raise TypeError("This is not a raw master key")

        key_spec_values = [self.encryption_algorithm]
        if self.encryption_algorithm == "aes":
            key_spec_values.append(str(key_bits))

        elif self.encryption_algorithm == "rsa":
            key_spec_values.append(self.padding_algorithm)

            if self.padding_hash is not None:
                key_spec_values.append(self.padding_hash)

        key_spec_name = "/".join(key_spec_values)

        if key_spec_name in _NOT_YET_IMPLEMENTED:
            raise NotImplementedError('Key spec "{}" is not yet available.')

        return _RAW_WRAPPING_KEY_ALGORITHMS[key_spec_name]

    def _wrapping_key(self, key_spec):
        # type: (KeySpec) -> WrappingKey
        """Build the  correct wrapping key if this is a raw master key.

        :param KeySpec key_spec: Key specification to use with this master key
        :return: Wrapping key to use
        :rtype: WrappingKey
        :raises TypeError: if this is not a raw master key specification
        """
        if not self.type_name == "raw":
            raise TypeError("This is not a raw master key")

        algorithm = self._wrapping_algorithm(key_spec.bits)
        material = key_spec.raw_material
        key_type = _RAW_ENCRYPTION_KEY_TYPE[key_spec.type_name]
        return WrappingKey(wrapping_algorithm=algorithm, wrapping_key=material, wrapping_key_type=key_type)

    def _raw_master_key_from_spec(self, keys):
        # type: (KeysManifest) -> RawMasterKey
        """Build a raw master key using this specification.

        :param KeySpec key_spec: Key specification to use with this master key
        :return: Raw master key based on this specification
        :rtype: RawMasterKey
        :raises TypeError: if this is not a raw master key specification
        """
        if not self.type_name == "raw":
            raise TypeError("This is not a raw master key")

        key_spec = keys.key(self.key_name)
        wrapping_key = self._wrapping_key(key_spec)
        return RawMasterKey(provider_id=self.provider_id, key_id=key_spec.key_id, wrapping_key=wrapping_key)

    def _kms_master_key_from_spec(self, keys):
        # type: (KeysManifest) -> KMSMasterKey
        """Build an AWS KMS master key using this specification.

        :param KeySpec key_spec: Key specification to use with this master key
        :return: AWS KMS master key based on this specification
        :rtype: KMSMasterKey
        :raises TypeError: if this is not an AWS KMS master key specification
        """
        if not self.type_name == "aws-kms":
            raise TypeError("This is not an AWS KMS master key")

        key_spec = keys.key(self.key_name)
        return KMS_MASTER_KEY_PROVIDER.master_key(key_id=key_spec.key_id)

    def _kms_mrk_aware_master_key_from_spec(self, keys):
        # type: (KeysManifest) -> KMSMasterKey
        """Build an AWS KMS master key using this specification.

        :param KeySpec key_spec: Key specification to use with this master key
        :return: AWS KMS master key based on this specification
        :rtype: KMSMasterKey
        :raises TypeError: if this is not an AWS KMS master key specification
        """
        if not self.type_name == "aws-kms-mrk-aware":
            raise TypeError("This is not an AWS KMS MRK-aware master key")

        key_spec = keys.key(self.key_name)
        return KMS_MRK_AWARE_MASTER_KEY_PROVIDER.master_key(key_id=key_spec.key_id)

    def _kms_mrk_aware_discovery_master_key_from_spec(self, _keys):
        # type: (KeysManifest) -> KMSMasterKey
        """Build an AWS KMS master key using this specification.

        :param KeySpec key_spec: Key specification to use with this master key
        :return: AWS KMS master key based on this specification
        :rtype: KMSMasterKey
        :raises TypeError: if this is not an AWS KMS master key specification
        """
        if not self.type_name == "aws-kms-mrk-aware-discovery":
            raise TypeError("This is not an AWS KMS MRK-aware discovery master key")

        return MRKAwareDiscoveryAwsKmsMasterKeyProvider(
            discovery_region=self.default_mrk_region, discovery_filter=self.discovery_filter
        )

    _MASTER_KEY_LOADERS = {
        "aws-kms": _kms_master_key_from_spec,
        "aws-kms-mrk-aware": _kms_mrk_aware_master_key_from_spec,
        "aws-kms-mrk-aware-discovery": _kms_mrk_aware_discovery_master_key_from_spec,
        "raw": _raw_master_key_from_spec,
    }

    def master_key(self, keys):
        # type: (KeysManifest) -> MasterKeyProvider
        """Build a master key using this specification.

        :param KeysManifest keys: Loaded key materials
        """
        key_loader = self._MASTER_KEY_LOADERS[self.type_name]
        return key_loader(self, keys)

    @property
    def scenario_spec(self):
        # type: () -> MASTER_KEY_SPEC
        """Build a master key specification describing this master key.

        :return: Master key specification JSON
        :rtype: dict
        """
        spec = {"type": self.type_name}
        if self.type_name == "aws-kms-mrk-aware-discovery":
            spec["default-mrk-region"] = self.default_mrk_region
            if self.discovery_filter:
                spec["aws-kms-discovery-filter"] = MasterKeySpec._discovery_filter_spec(self.discovery_filter)
        else:
            spec["key"] = self.key_name

        if self.type_name != "aws-kms":
            spec.update(
                {
                    "provider-id": self.provider_id,
                    "encryption-algorithm": self.encryption_algorithm,
                    "padding-algorithm": self.padding_algorithm,
                }
            )
            if self.padding_hash is not None:
                spec["padding-hash"] = self.padding_hash

        return spec


def master_key_provider_from_master_key_specs(keys, master_key_specs):
    # type: (KeysManifest, Iterable[MasterKeySpec]) -> MasterKeyProvider
    """Build and combine all master key providers identified by the provided specs and
    using the provided keys.

    :param KeysManifest keys: Loaded keys manifest
    :param master_key_specs: Master key specs from which to load master keys
    :type master_key_specs: iterable of MasterKeySpec
    :return: Master key provider combining all loaded master keys
    :rtype: MasterKeyProvider
    """
    master_keys = []
    for spec in master_key_specs:
        try:
            master_keys.append(spec.master_key(keys))
        # If spec is not a valid master key
        # (e.g. hierarchical keyring)
        # do not make a master key
        except KeyError:
            pass
    if len(master_keys) == 0:
        return None
    primary = master_keys[0]
    others = master_keys[1:]
    for master_key in others:
        primary.add_master_key_provider(master_key)
    return primary
