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
AWS Encryption SDK Decrypt Message Generation manifest handler.

Described in AWS Crypto Tools Test Vector Framework feature #0006 AWS Encryption SDK Decrypt Message Generation.
"""
import json
import os
import uuid

import attr
import six
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager

from awses_test_vectors.internal.defaults import ENCODING
from awses_test_vectors.internal.util import (
    dictionary_validator,
    file_reader,
    file_writer,
    iterable_validator,
    membership_validator,
    validate_manifest_type,
)
from awses_test_vectors.manifests.full_message.decrypt import (
    MessageDecryptionManifest,
    MessageDecryptionTestResult,
    MessageDecryptionTestScenario,
)
from awses_test_vectors.manifests.full_message.encrypt import MessageEncryptionTestScenario
from awses_test_vectors.manifests.keys import KeysManifest
from awses_test_vectors.manifests.master_key import MasterKeySpec, master_key_provider_from_master_key_specs


try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import IO, Callable, Dict, Iterable, Optional  # noqa pylint: disable=unused-import

    from awses_test_vectors.internal.mypy_types import (  # noqa pylint: disable=unused-import
        ENCRYPT_SCENARIO_SPEC,
        PLAINTEXTS_SPEC,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

SUPPORTED_VERSIONS = (1,)


class TamperingMethod:
    """Base class for all tampering methods."""

    @classmethod
    def from_tampering_spec(cls, spec):
        """Load from a tampering specification"""
        if spec is None:
            return TamperingMethod()
        ((tampering_tag, tampering_values_spec),) = spec.items()
        if tampering_tag == "change-edk-provider-info":
            return ChangeEDKProviderInfoTamperingMethod.from_values_spec(tampering_values_spec)
        raise ValueError("Unrecognized tampering method tag: " + tampering_tag)

    # pylint: disable=R0201
    def run_scenario_with_tampering(self, ciphertext_writer, generation_scenario, plaintext_uri):
        """
        Run a given scenario, tampering with the input or the result.

        return: a list of (ciphertext, result) pairs
        """
        materials_manager = DefaultCryptoMaterialsManager(generation_scenario.encryption_scenario.master_key_provider)
        ciphertext_to_decrypt = generation_scenario.encryption_scenario.run(materials_manager)
        if generation_scenario.result:
            expected_result = generation_scenario.result
        else:
            expected_result = MessageDecryptionTestResult.expect_output(
                plaintext_uri=plaintext_uri, plaintext=generation_scenario.encryption_scenario.plaintext
            )
        return [
            generation_scenario.decryption_test_scenario_pair(
                ciphertext_writer, ciphertext_to_decrypt, expected_result
            )
        ]


class ChangeEDKProviderInfoTamperingMethod(TamperingMethod):
    """Tampering method that changes the provider info on all EDKs."""

    new_provider_infos = attr.ib(validator=iterable_validator(list, six.string_types))

    def __init__(self, new_provider_infos):
        """Create a new instance for a given new provider info value."""
        self.new_provider_infos = new_provider_infos

    @classmethod
    def from_values_spec(cls, values_spec):
        """Load from a tampering parameters specification"""
        return ChangeEDKProviderInfoTamperingMethod(values_spec)

    # pylint: disable=R0201
    def run_scenario_with_tampering(self, ciphertext_writer, generation_scenario, _plaintext_uri):
        """
        Run a given scenario, tampering with the input or the result.

        return: a list of (ciphertext, result) pairs.
        """
        return [
            self.run_scenario_with_new_provider_info(ciphertext_writer, generation_scenario, new_provider_info)
            for new_provider_info in self.new_provider_infos
        ]

    def run_scenario_with_new_provider_info(self, ciphertext_writer, generation_scenario, new_provider_info):
        """Run with tampering for a specific new provider info value"""
        tampering_materials_manager = ProviderInfoChangingCryptoMaterialsManager(
            generation_scenario.encryption_scenario.master_key_provider, new_provider_info
        )
        ciphertext_to_decrypt = generation_scenario.encryption_scenario.run(tampering_materials_manager)
        expected_result = MessageDecryptionTestResult.expect_error(
            "Incorrect encrypted data key provider info: " + new_provider_info
        )
        return generation_scenario.decryption_test_scenario_pair(
            ciphertext_writer, ciphertext_to_decrypt, expected_result
        )


class ProviderInfoChangingCryptoMaterialsManager(CryptoMaterialsManager):
    """
    Custom CMM that modifies the provider info field on EDKS.

    THIS IS ONLY USED TO CREATE INVALID MESSAGES and should never be used in
    production!
    """

    wrapped_default_cmm = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsManager))
    new_provider_info = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __init__(self, master_key_provider, new_provider_info):
        """
        Create a new CMM that wraps a new DefaultCryptoMaterialsManager
        based on the given master key provider.
        """
        self.wrapped_default_cmm = DefaultCryptoMaterialsManager(master_key_provider)
        self.new_provider_info = new_provider_info

    def get_encryption_materials(self, request):
        """
        Request materials from the wrapped default CMM, and then change the provider info
        on each EDK.
        """
        result = self.wrapped_default_cmm.get_encryption_materials(request)
        for encrypted_data_key in result.encrypted_data_keys:
            encrypted_data_key.provider_info = self.new_provider_info
        return result

    def decrypt_materials(self, request):
        """Thunks to the wrapped default CMM"""
        return self.wrapped_default_cmm.decrypt_materials(request)


@attr.s
class MessageDecryptionTestScenarioGenerator(object):
    # pylint: disable=too-many-instance-attributes
    """Data class for a single full message decrypt test scenario.

    Handles serialization and deserialization to and from manifest specs.

    :param MessageEncryptionTestScenario encryption_scenario: Encryption parameters
    :param tampering_method: Optional method used to tamper with the ciphertext
    :type tampering_method: :class:`TamperingMethod`
    :param decryption_master_key_specs: Iterable of master key specifications
    :type decryption_master_key_specs: iterable of :class:`MasterKeySpec`
    :param MasterKeyProvider decryption_master_key_provider:
    :param result:
    """

    encryption_scenario = attr.ib(validator=attr.validators.instance_of(MessageEncryptionTestScenario))
    tampering_method = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(TamperingMethod)))
    decryption_master_key_specs = attr.ib(validator=iterable_validator(list, MasterKeySpec))
    decryption_master_key_provider = attr.ib(validator=attr.validators.instance_of(MasterKeyProvider))
    result = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(MessageDecryptionTestResult)))

    @classmethod
    def from_scenario(cls, scenario, keys, plaintexts):
        """Load from a scenario specification.

        :param dict scenario: Scenario specification JSON
        :param KeysManifest keys: Loaded keys
        :param dict plaintexts: Mapping of plaintext names to plaintext values
        :return: Loaded test scenario
        :rtype: MessageDecryptionTestScenarioGenerator
        """
        encryption_scenario_spec = scenario["encryption-scenario"]
        encryption_scenario = MessageEncryptionTestScenario.from_scenario(encryption_scenario_spec, keys, plaintexts)
        tampering = scenario.get("tampering")
        tampering_method = TamperingMethod.from_tampering_spec(tampering)
        if "decryption-master-keys" in scenario:
            decryption_master_key_specs = [
                MasterKeySpec.from_scenario(spec) for spec in scenario["decryption-master-keys"]
            ]
            decryption_master_key_provider = master_key_provider_from_master_key_specs(
                keys, decryption_master_key_specs
            )
        else:
            decryption_master_key_specs = encryption_scenario.master_key_specs
            decryption_master_key_provider = encryption_scenario.master_key_provider
        result_spec = scenario.get("result")
        result = MessageDecryptionTestResult.from_result_spec(result_spec, None) if result_spec else None

        return cls(
            encryption_scenario=encryption_scenario,
            tampering_method=tampering_method,
            decryption_master_key_specs=decryption_master_key_specs,
            decryption_master_key_provider=decryption_master_key_provider,
            result=result,
        )

    def run(self, ciphertext_writer, plaintext_uri):
        """Run this scenario, writing the resulting ciphertext with ``ciphertext_writer`` and returning
        a :class:`MessageDecryptionTestScenario` that describes the matching decrypt scenario.

        :param callable ciphertext_writer: Callable that will write the requested named ciphertext and
            return a URI locating the written data
        :param str plaintext_uri: URI locating the written plaintext data for this scenario
        :return: Decrypt test scenario that describes the generated scenario
        :rtype: MessageDecryptionTestScenario
        """
        return dict(self.tampering_method.run_scenario_with_tampering(ciphertext_writer, self, plaintext_uri))

    def decryption_test_scenario_pair(
        self, ciphertext_writer, ciphertext_to_decrypt, expected_result
    ):
        """Create a new (name, decryption scenario) pair"""
        ciphertext_name = str(uuid.uuid4())
        ciphertext_uri = ciphertext_writer(ciphertext_name, ciphertext_to_decrypt)

        return (
            ciphertext_name,
            MessageDecryptionTestScenario(
                ciphertext_uri=ciphertext_uri,
                ciphertext=ciphertext_to_decrypt,
                master_key_specs=self.decryption_master_key_specs,
                master_key_provider=self.decryption_master_key_provider,
                result=expected_result,
            ),
        )


@attr.s
class MessageDecryptionGenerationManifest(object):
    """AWS Encryption SDK Decryption Message Generation manifest handler.

    Described in AWS Crypto Tools Test Vector Framework feature #0006 AWS Encryption SDK Decrypt Message Generation.

    :param int version: Version of this manifest
    :param KeysManifest keys: Loaded keys
    :param dict plaintexts: Mapping of plaintext names to plaintext values
    :param dict tests: Mapping of test scenario names to :class:`MessageDecryptionGenerationManifest`s
    """

    version = attr.ib(validator=membership_validator(SUPPORTED_VERSIONS))
    keys = attr.ib(validator=attr.validators.instance_of(KeysManifest))
    plaintexts = attr.ib(validator=dictionary_validator(six.string_types, six.binary_type))
    tests = attr.ib(validator=dictionary_validator(six.string_types, MessageDecryptionTestScenarioGenerator))
    type_name = "awses-decrypt-generate"

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
        # type: (IO) -> MessageDecryptionGenerationManifest
        """Load from a file containing a full message encrypt manifest.

        :param file input_file: File object for file containing JSON manifest
        :return: Loaded manifest
        :rtype: MessageEncryptionManifest
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
        tests = {}
        for name, scenario in raw_manifest["tests"].items():
            try:
                tests[name] = MessageDecryptionTestScenarioGenerator.from_scenario(
                    scenario=scenario, keys=keys, plaintexts=plaintexts
                )
            except NotImplementedError:
                continue
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
            decrypt_scenario_name: decrypt_scenario
            for name, scenario in self.tests.items()
            for decrypt_scenario_name, decrypt_scenario in scenario.run(
                ciphertext_writer, plaintext_uris[scenario.encryption_scenario.plaintext_name]
            ).items()
        }

        decrypt_manifest = MessageDecryptionManifest(
            keys_uri="file://keys.json", keys=self.keys, test_scenarios=test_scenarios
        )

        root_writer("manifest.json", json.dumps(decrypt_manifest.manifest_spec, indent=json_indent).encode(ENCODING))
