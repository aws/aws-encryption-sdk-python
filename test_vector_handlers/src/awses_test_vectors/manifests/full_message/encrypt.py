# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
AWS Encryption SDK Encrypt Message manifest handler.

Described in AWS Crypto Tools Test Vector Framework feature #0003 AWS Encryption SDK Encrypt Message.
"""
import json
import os

import attr
import aws_encryption_sdk
import six

from aws_encryption_sdk.key_providers.base import MasterKeyProvider

from awses_test_vectors.internal.defaults import ENCODING
from awses_test_vectors.internal.util import (
    algorithm_suite_from_string_id,
    dictionary_validator,
    file_reader,
    iterable_validator,
    membership_validator,
    validate_manifest_type,
)
from awses_test_vectors.manifests.keys import KeysManifest
from awses_test_vectors.manifests.master_key import MasterKeySpec, master_key_provider_from_master_key_specs


try:
    from aws_encryption_sdk.identifiers import AlgorithmSuite, CommitmentPolicy
except ImportError:
    from aws_encryption_sdk.identifiers import Algorithm as AlgorithmSuite

try:
    from aws_cryptographic_materialproviders.mpl.references import (
        IKeyring,
    )

    from awses_test_vectors.manifests.mpl_keyring import KeyringSpec, keyring_from_master_key_specs

    _HAS_MPL = True
except ImportError as e:
    print(e)
    _HAS_MPL = False


try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import IO, Callable, Dict, Iterable, Optional  # noqa pylint: disable=unused-import

    from awses_test_vectors.internal.mypy_types import (  # noqa pylint: disable=unused-import
        ENCRYPT_SCENARIO_SPEC,
        PLAINTEXTS_SPEC,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

SUPPORTED_VERSIONS = (2,)


@attr.s
class MessageEncryptionTestScenario(object):
    # pylint: disable=too-many-instance-attributes
    """Data class for a single full message decrypt test scenario.

    Handles serialization and deserialization to and from manifest specs.

    :param str plaintext_name: Identifying name of plaintext
    :param bytes plaintext: Binary plaintext data
    :param AlgorithmSuite algorithm: Algorithm suite to use
    :param int frame_size: Frame size to use
    :param dict encryption_context: Encryption context to use
    :param master_key_specs: Iterable of loaded master key specifications
    :type master_key_specs: iterable of :class:`MasterKeySpec`
    :param Callable master_key_provider_fn:
    """

    plaintext_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    plaintext = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    algorithm = attr.ib(validator=attr.validators.instance_of(AlgorithmSuite))
    frame_size = attr.ib(validator=attr.validators.instance_of(int))
    encryption_context = attr.ib(validator=dictionary_validator(six.string_types, six.string_types))
    master_key_specs = attr.ib(validator=iterable_validator(list, MasterKeySpec))
    master_key_provider_fn = attr.ib(validator=attr.validators.is_callable())
    keyrings = attr.ib(validator=attr.validators.instance_of(bool))
    cmm = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def from_scenario(cls, scenario, keys, plaintexts, keyrings, keys_uri):
        # pylint: disable=too-many-arguments
        # type: (ENCRYPT_SCENARIO_SPEC, KeysManifest, Dict[str, bytes], bool, str) -> MessageEncryptionTestScenario
        """Load from a scenario specification.

        :param dict scenario: Scenario specification JSON
        :param KeysManifest keys: Loaded keys
        :param dict plaintexts: Mapping of plaintext names to plaintext values
        :param bool keyrings: True if should encrypt with keyring interfaces; False otherwise
        :param str keys_uri: Path to the keys manifest
        :return: Loaded test scenario
        :rtype: MessageEncryptionTestScenario
        """
        algorithm = algorithm_suite_from_string_id(scenario["algorithm"])

        if keyrings:
            master_key_specs = [
                KeyringSpec.from_scenario(spec) for spec in scenario["master-keys"]
            ]
        else:
            master_key_specs = [
                MasterKeySpec.from_scenario(spec) for spec in scenario["master-keys"]
            ]

        def master_key_provider_fn():
            if keyrings:
                return keyring_from_master_key_specs(keys_uri, master_key_specs, "encrypt")
            return master_key_provider_from_master_key_specs(keys, master_key_specs)

        # MPL test vectors add CMM types to the test vectors manifests
        if "cmm" in scenario:
            if scenario["cmm"] == "Default":
                # Master keys and keyrings can handle default CMM
                cmm_type = scenario["cmm"]
            elif scenario["cmm"] == "RequiredEncryptionContext":
                # Skip RequiredEncryptionContext CMM for master keys;
                # RequiredEncryptionContext is unsupported for master keys.
                # Caller logic should expect `None` to mean "no scenario".
                if keyrings:
                    cmm_type = scenario["cmm"]
                else:
                    return None
            else:
                raise ValueError("Unrecognized cmm_type: " + cmm_type)
        else:
            # If unspecified, set "Default" as the default
            cmm_type = "Default"

        return cls(
            plaintext_name=scenario["plaintext"],
            plaintext=plaintexts[scenario["plaintext"]],
            algorithm=algorithm,
            frame_size=scenario["frame-size"],
            encryption_context=scenario["encryption-context"],
            master_key_specs=master_key_specs,
            master_key_provider_fn=master_key_provider_fn,
            keyrings=keyrings,
            cmm=cmm_type,
        )

    def run(self, materials_manager=None):
        """Run this scenario, writing the resulting ciphertext with ``ciphertext_writer`` and returning
        a :class:`MessageDecryptionTestScenario` that describes the matching decrypt scenario.

        :param callable ciphertext_writer: Callable that will write the requested named ciphertext and
            return a URI locating the written data
        :param str plaintext_uri: URI locating the written plaintext data for this scenario
        :return: Decrypt test scenario that describes the generated scenario
        :rtype: MessageDecryptionTestScenario
        """
        commitment_policy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
        if self.algorithm.is_committing():
            commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT

        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=commitment_policy)
        encrypt_kwargs = dict(
            source=self.plaintext,
            algorithm=self.algorithm,
            frame_length=self.frame_size,
            encryption_context=self.encryption_context,
        )
        if materials_manager:
            encrypt_kwargs["materials_manager"] = materials_manager
        elif isinstance(self.master_key_provider_fn(), MasterKeyProvider):
            encrypt_kwargs["key_provider"] = self.master_key_provider_fn()
        elif _HAS_MPL and isinstance(self.master_key_provider_fn(), IKeyring):
            encrypt_kwargs["keyring"] = self.master_key_provider_fn()
        else:
            raise TypeError(f"Unrecognized master_key_provider_fn return type: {self.master_key_provider_fn()}")
        ciphertext, _header = client.encrypt(**encrypt_kwargs)
        return ciphertext


@attr.s
class MessageEncryptionManifest(object):
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
    tests = attr.ib(validator=dictionary_validator(six.string_types, MessageEncryptionTestScenario))
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
    def from_file(cls, input_file, keyrings):
        # type: (IO) -> MessageEncryptionManifest
        """Load frome a file containing a full message encrypt manifest.

        :param file input_file: File object for file containing JSON manifest
        :param bool keyrings: True if should encrypt with keyring interfaces; False otherwise
        :return: Loaded manifest
        :rtype: MessageEncryptionManifest
        """
        raw_manifest = json.load(input_file)
        validate_manifest_type(
            type_name=cls.type_name, manifest_version=raw_manifest["manifest"], supported_versions=SUPPORTED_VERSIONS
        )

        parent_dir = os.path.abspath(os.path.dirname(input_file.name))
        reader = file_reader(parent_dir)

        # MPL TestVector keyring needs to know the path to the keys file
        keys_uri = raw_manifest["keys"]
        keys_filename = keys_uri.replace("file://", "")
        keys_abs_path = os.path.join(parent_dir, keys_filename)

        raw_keys_manifest = json.loads(reader(keys_uri).decode(ENCODING))
        keys = KeysManifest.from_manifest_spec(raw_keys_manifest)
        plaintexts = cls._generate_plaintexts(raw_manifest["plaintexts"])
        tests = {}
        for name, scenario in raw_manifest["tests"].items():
            try:
                tests[name] = MessageEncryptionTestScenario.from_scenario(
                    scenario=scenario, keys=keys, plaintexts=plaintexts, keyrings=keyrings, keys_uri=keys_abs_path
                )
            except NotImplementedError:
                continue
        return cls(version=raw_manifest["manifest"]["version"], keys=keys, plaintexts=plaintexts, tests=tests)

    def run(self):
        # () -> None
        """Process all scenarios in this manifest."""
        for _, scenario in self.tests.items():
            scenario.run()
