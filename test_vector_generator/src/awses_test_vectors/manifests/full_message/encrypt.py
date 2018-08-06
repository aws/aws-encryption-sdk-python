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
AWS Encryption SDK Encrypt Message manifest handler.

Described in AWS Crypto Tools Test Vector Framework feature #0003 AWS Encryption SDK Encrypt Message.
"""
import binascii
import json
import os
import uuid

import attr
import aws_encryption_sdk
import six
from aws_encryption_sdk.identifiers import AlgorithmSuite
from aws_encryption_sdk.key_providers.base import MasterKeyProvider

from awses_test_vectors.internal.defaults import ENCODING
from awses_test_vectors.internal.util import (
    algorithm_suite_from_string_id,
    dictionary_validator,
    file_reader,
    file_writer,
    iterable_validator,
    membership_validator,
    validate_manifest_type,
)
from awses_test_vectors.manifests.full_message.decrypt import DecryptMessageManifest, DecryptTestScenario
from awses_test_vectors.manifests.keys import KeysManifest
from awses_test_vectors.manifests.master_key import MasterKeySpec, master_key_provider_from_master_key_specs

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, Dict, IO, Iterable, Optional  # noqa pylint: disable=unused-import
    from awses_test_vectors.internal.mypy_types import (  # noqa pylint: disable=unused-import
        ENCRYPT_SCENARIO_SPEC,
        PLAINTEXTS_SPEC,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

SUPPORTED_VERSIONS = (1,)


@attr.s
class EncryptTestScenario(object):
    """Data class for a single full message decrypt test scenario.

    Handles serialization and deserialization to and from manifest specs.

    :param str plaintext_name: Identifying name of plaintext
    :param bytes plaintext: Binary plaintext data
    :param AlgorithmSuite algorithm: Algorithm suite to use
    :param int frame_size: Frame size to use
    :param dict encryption_context: Encryption context to use
    :param master_key_specs: Iterable of loaded master key specifications
    :type master_key_specs: iterable of :class:`MasterKeySpec`
    :param MasterKeyProvider master_key_provider:
    """

    plaintext_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    plaintext = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    algorithm = attr.ib(validator=attr.validators.instance_of(AlgorithmSuite))
    frame_size = attr.ib(validator=attr.validators.instance_of(int))
    encryption_context = attr.ib(validator=dictionary_validator(six.string_types, six.string_types))
    master_key_specs = attr.ib(validator=iterable_validator(list, MasterKeySpec))
    master_key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyProvider))

    @classmethod
    def from_scenario(cls, scenario, keys, plaintexts):
        # type: (ENCRYPT_SCENARIO_SPEC, KeysManifest, Dict[str, bytes]) -> EncryptTestScenario
        """Load from a scenario specification.

        :param dict scenario: Scenario specification JSON
        :param KeysManifest keys: Loaded keys
        :param dict plaintexts: Mapping of plaintext names to plaintext values
        :return: Loaded test scenario
        :rtype: EncryptTestScenario
        """
        algorithm = algorithm_suite_from_string_id(scenario["algorithm"])
        master_key_specs = [MasterKeySpec.from_scenario(spec) for spec in scenario["master-keys"]]
        master_key_provider = master_key_provider_from_master_key_specs(keys, master_key_specs)

        return cls(
            plaintext_name=scenario["plaintext"],
            plaintext=plaintexts[scenario["plaintext"]],
            algorithm=algorithm,
            frame_size=scenario["frame-size"],
            encryption_context=scenario["encryption-context"],
            master_key_specs=master_key_specs,
            master_key_provider=master_key_provider,
        )

    @property
    def scenario_spec(self):
        # type: () -> ENCRYPT_SCENARIO_SPEC
        """Build a scenario specification describing this test scenario.

        :return: Scenario specification JSON
        :rtype: dict
        """
        return {
            "plaintext": self.plaintext_name,
            "algorithm": binascii.hexlify(self.algorithm.id_as_bytes()),
            "frame-size": self.frame_size,
            "encryption-context": self.encryption_context,
            "master-keys": [spec.scenario_spec for spec in self.master_key_specs],
        }

    def run(self, ciphertext_writer, plaintext_uri):
        """Run this scenario, writing the resulting ciphertext with ``ciphertext_writer`` and returning
        a :class:`DecryptTestScenario` that describes the matching decrypt scenario.

        :param callable ciphertext_writer: Callable that will write the requested named ciphertext and
            return a URI locating the written data
        :param str plaintext_uri: URI locating the written plaintext data for this scenario
        :return: Decrypt test scenario that describes the generated scenario
        :rtype: DecryptTestScenario
        """
        ciphertext, _header = aws_encryption_sdk.encrypt(
            source=self.plaintext,
            algorithm=self.algorithm,
            frame_length=self.frame_size,
            encryption_context=self.encryption_context,
            key_provider=self.master_key_provider,
        )

        ciphertext_name = str(uuid.uuid4())
        ciphertext_uri = ciphertext_writer(ciphertext_name, ciphertext)

        return DecryptTestScenario(
            plaintext_uri=plaintext_uri,
            plaintext=self.plaintext,
            ciphertext_uri=ciphertext_uri,
            ciphertext=ciphertext,
            master_key_specs=self.master_key_specs,
            master_key_provider=self.master_key_provider,
        )


@attr.s
class EncryptMessageManifest(object):
    """AWS Encryption SDK Encrypt Message manifest handler.

    Described in AWS Crypto Tools Test Vector Framework feature #0003 AWS Encryption SDK Encrypt Message.

    :param int version: Version of this manifest
    :param KeysManifest keys: Loaded keys
    :param dict plaintexts: Mapping of plaintext names to plaintext values
    :param dict tests: Mapping of test scenario names to :class:`EncryptTextScenario`s
    """

    version = attr.ib(validator=membership_validator(SUPPORTED_VERSIONS))
    keys = attr.ib(validator=attr.validators.instance_of(KeysManifest))
    plaintexts = attr.ib(validator=dictionary_validator(six.string_types, six.binary_type))
    tests = attr.ib(validator=dictionary_validator(six.string_types, EncryptTestScenario))
    type_name = "awses-encrypt"

    @staticmethod
    def _generate_plaintexts(plaintexts_specs):
        # type: (PLAINTEXTS_SPEC) -> Dict[str, bytes]
        """Generate required plaintext values.

        :param dict plaintexts_specs: Mapping of plaintext name to size in bytes
        :return: Mapping of plaintext name to randomly generated bytes
        :rtype: dict
        """
        return {name: os.urandom(size) for name, size in plaintexts_specs.items()}

    @classmethod
    def from_file(cls, input_file):
        # type: (IO) -> EncryptMessageManifest
        """Load frome a file containing a full message encrypt manifest.

        :param file input_file: File object for file containing JSON manifest
        :return: Loaded manifest
        :rtype: EncryptMessageManifest
        """
        raw_manifest = json.load(input_file)
        validate_manifest_type(
            type_name=cls.type_name, manifest_version=raw_manifest["manifest"], supported_versions=SUPPORTED_VERSIONS
        )

        parent_dir = os.path.abspath(os.path.dirname(input_file.name))
        reader = file_reader(parent_dir)
        raw_keys_manifest = json.loads(reader(raw_manifest["keys"]).decode(ENCODING))
        keys = KeysManifest.from_manifest_spec(raw_keys_manifest)
        plaintexts = cls._generate_plaintexts(raw_manifest["plaintexts"])
        tests = {
            name: EncryptTestScenario.from_scenario(scenario=scenario, keys=keys, plaintexts=plaintexts)
            for name, scenario in raw_manifest["tests"].items()
        }
        return cls(version=raw_manifest["manifest"]["version"], keys=keys, plaintexts=plaintexts, tests=tests)

    def run_and_write_to_dir(self, target_directory, json_indent=None):
        # type: (str, Optional[int]) -> None
        """Process all known encrypt test scenarios and write the resulting data and manifests to disk.

        :param str target_directory: Directory in which to write all output
        :param int json_indent: Number of spaces to indent JSON files (optional: default is to write minified)
        """
        root_dir = os.path.abspath(target_directory)
        root_writer = file_writer(root_dir)

        root_writer("keys.json", json.dumps(self.keys.manifest_spec, indent=json_indent).encode(ENCODING))

        plaintext_writer = file_writer(os.path.join(root_dir, "plaintexts"))
        plaintext_uris = {name: plaintext_writer(name, plaintext) for name, plaintext in self.plaintexts.items()}

        ciphertext_writer = file_writer(os.path.join(root_dir, "ciphertexts"))

        test_scenarios = {
            name: scenario.run(ciphertext_writer, plaintext_uris[scenario.plaintext_name])
            for name, scenario in self.tests.items()
        }

        decrypt_manifest = DecryptMessageManifest(
            keys_uri="file://keys.json", keys=self.keys, test_scenarios=test_scenarios
        )

        root_writer(
            "decrypt_message.json", json.dumps(decrypt_manifest.manifest_spec, indent=json_indent).encode(ENCODING)
        )
