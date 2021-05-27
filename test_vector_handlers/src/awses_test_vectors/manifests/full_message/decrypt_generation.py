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
from copy import copy
from enum import Enum

import attr
import six
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager

from awses_test_vectors.internal.defaults import ENCODING
from awses_test_vectors.internal.util import (
    dictionary_validator,
    file_reader,
    file_writer,
    membership_validator,
    validate_manifest_type,
)
from awses_test_vectors.manifests.full_message.decrypt import (
    DecryptionMethod,
    MessageDecryptionManifest,
    MessageDecryptionTestResult,
    MessageDecryptionTestScenario,
)
from awses_test_vectors.manifests.full_message.encrypt import MessageEncryptionTestScenario
from awses_test_vectors.manifests.keys import KeysManifest

try:
    from aws_encryption_sdk.identifiers import AlgorithmSuite
except ImportError:
    from aws_encryption_sdk.identifiers import Algorithm as AlgorithmSuite


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


class TamperingMethod(Enum):
    """Enumeration of transformations on valid messages to make them invalid."""

    TRUNCATE = "truncate"
    MUTATE = "mutate"
    HALF_SIGN = "half-sign"


BITS_PER_BYTE = 8


class HalfSigningCryptoMaterialsManager(CryptoMaterialsManager):
    """
    Custom CMM that generates materials for an unsigned algorithm suite
    that includes the "aws-crypto-public-key" encryption context.

    THIS IS ONLY USED TO CREATE INVALID MESSAGES and should never be used in
    production! It is imitating what a malicious decryptor without encryption
    permissions might do, to attempt to forge an unsigned message from a decrypted
    signed message, and therefore this is an important case for ESDKs to reject.
    """

    wrapped_default_cmm = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsManager))

    def __init__(self, master_key_provider):
        """
        Create a new CMM that wraps a new DefaultCryptoMaterialsManager
        based on the given master key provider.
        """
        self.wrapped_default_cmm = DefaultCryptoMaterialsManager(master_key_provider)

    def get_encryption_materials(self, request):
        """
        Generate half-signing materials by requesting signing materials
        from the wrapped default CMM, and then changing the algorithm suite
        and removing the signing key from teh result.
        """
        if request.algorithm == AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
            signing_request = copy(request)
            signing_request.algorithm = AlgorithmSuite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384

            result = self.wrapped_default_cmm.get_encryption_materials(signing_request)
            result.algorithm = request.algorithm
            result.signing_key = None

            return result

        raise NotImplementedError(
            "The half-sign tampering method is only supported on the "
            "AES_256_GCM_HKDF_SHA512_COMMIT_KEY algorithm suite."
        )

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
    :param decryption_method:
    :param result:
    """

    encryption_scenario = attr.ib(validator=attr.validators.instance_of(MessageEncryptionTestScenario))
    tampering_method = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(TamperingMethod)))
    decryption_method = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(DecryptionMethod)))
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
        tampering_method = TamperingMethod(tampering) if tampering else None
        decryption_method_spec = scenario.get("decryption-method")
        decryption_method = DecryptionMethod(decryption_method_spec) if decryption_method_spec else None
        result_spec = scenario.get("result")
        result = MessageDecryptionTestResult.from_result_spec(result_spec, None) if result_spec else None

        return cls(
            encryption_scenario=encryption_scenario,
            tampering_method=tampering_method,
            decryption_method=decryption_method,
            result=result,
        )

    @classmethod
    def flip_bit(cls, ciphertext, bit):
        """Flip only the given bit in the given ciphertext"""
        byte_index, bit_index = divmod(bit, BITS_PER_BYTE)
        result = bytearray(ciphertext)
        result[byte_index] ^= 1 << (BITS_PER_BYTE - bit_index - 1)
        return bytes(result)

    def run(self, ciphertext_writer, plaintext_uri):
        """Run this scenario, writing the resulting ciphertext with ``ciphertext_writer`` and returning
        a :class:`MessageDecryptionTestScenario` that describes the matching decrypt scenario.

        :param callable ciphertext_writer: Callable that will write the requested named ciphertext and
            return a URI locating the written data
        :param str plaintext_uri: URI locating the written plaintext data for this scenario
        :return: Decrypt test scenario that describes the generated scenario
        :rtype: MessageDecryptionTestScenario
        """
        if self.result:
            expected_result = self.result
        else:
            expected_result = MessageDecryptionTestResult.expect_output(
                plaintext_uri=plaintext_uri, plaintext=self.encryption_scenario.plaintext
            )

        materials_manager = None
        if self.tampering_method == TamperingMethod.HALF_SIGN:
            materials_manager = HalfSigningCryptoMaterialsManager(self.encryption_scenario.master_key_provider)
            expected_result = MessageDecryptionTestResult.expect_error(
                "Unsigned message using a data key with a public key"
            )

        ciphertext = self.encryption_scenario.run(materials_manager)

        def decryption_test_scenario_pair(ciphertext_to_decrypt, expected_result):
            ciphertext_name = str(uuid.uuid4())
            ciphertext_uri = ciphertext_writer(ciphertext_name, ciphertext_to_decrypt)

            return (
                ciphertext_name,
                MessageDecryptionTestScenario(
                    ciphertext_uri=ciphertext_uri,
                    ciphertext=ciphertext_to_decrypt,
                    master_key_specs=self.encryption_scenario.master_key_specs,
                    master_key_provider=self.encryption_scenario.master_key_provider,
                    decryption_method=self.decryption_method,
                    result=expected_result,
                ),
            )

        if self.tampering_method == TamperingMethod.TRUNCATE:
            return dict(
                decryption_test_scenario_pair(
                    ciphertext[0:length],
                    MessageDecryptionTestResult.expect_error("Truncated at byte {}".format(length)),
                )
                for length in range(1, len(ciphertext))
            )
        if self.tampering_method == TamperingMethod.MUTATE:
            return dict(
                decryption_test_scenario_pair(
                    self.flip_bit(ciphertext, bit),
                    MessageDecryptionTestResult.expect_error("Bit {} flipped".format(bit)),
                )
                for bit in range(0, len(ciphertext) * BITS_PER_BYTE)
            )

        return dict([decryption_test_scenario_pair(ciphertext, expected_result)])


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
