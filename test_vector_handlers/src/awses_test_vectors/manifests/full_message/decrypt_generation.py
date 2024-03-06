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

import attr
import six
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager

try:
    from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
    from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
    from aws_cryptographic_materialproviders.mpl.references import (
        IKeyring,
        CryptographicMaterialsManager,
    )
    from aws_cryptographic_materialproviders.mpl.models import (
        CreateDefaultCryptographicMaterialsManagerInput,
    )
    from aws_encryption_sdk.materials_managers.mpl.cmm import CryptoMaterialsManagerFromMPL

    from awses_test_vectors.manifests.mpl_keyring import keyring_from_master_key_specs

    _HAS_MPL = True
except ImportError as e:
    _HAS_MPL = False


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

SUPPORTED_VERSIONS = (2,)


class TamperingMethod:
    """Base class for all tampering methods."""

    @classmethod
    def from_tampering_spec(cls, spec):
        """Load from a tampering specification"""
        if spec is None:
            return TamperingMethod()
        if spec == "truncate":
            return TruncateTamperingMethod()
        if spec == "mutate":
            return MutateTamperingMethod()
        if spec == "half-sign":
            return HalfSigningTamperingMethod()
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
        key_provider = generation_scenario.encryption_scenario.master_key_provider_fn()
        if isinstance(key_provider, MasterKeyProvider):
            materials_manager = DefaultCryptoMaterialsManager(
                key_provider
            )
        elif isinstance(key_provider, IKeyring):
            mpl = AwsCryptographicMaterialProviders(MaterialProvidersConfig())
            mpl_cmm = mpl.create_default_cryptographic_materials_manager(
                CreateDefaultCryptographicMaterialsManagerInput(
                    keyring=key_provider
                )
            )
            materials_manager = CryptoMaterialsManagerFromMPL(
                mpl_cmm=mpl_cmm
            )
        else:
            raise ValueError(f"Unrecognized master_key_provider_fn return type: {str(key_provider)}")
        ciphertext_to_decrypt = generation_scenario.encryption_scenario.run(materials_manager)
        if generation_scenario.result:
            expected_result = generation_scenario.result
        else:
            expected_result = MessageDecryptionTestResult.expect_output(
                plaintext_uri=plaintext_uri, plaintext=generation_scenario.encryption_scenario.plaintext
            )
        return [
            generation_scenario.decryption_test_scenario_pair(ciphertext_writer, ciphertext_to_decrypt, expected_result)
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
        master_key_provider = generation_scenario.encryption_scenario.master_key_provider_fn()

        # Use a caching CMM to avoid generating a new data key every time.
        cache = LocalCryptoMaterialsCache(10)
        caching_cmm = CachingCryptoMaterialsManager(
            master_key_provider=master_key_provider,
            cache=cache,
            max_age=60.0,
            max_messages_encrypted=100,
        )
        return [
            self.run_scenario_with_new_provider_info(
                ciphertext_writer, generation_scenario, caching_cmm, new_provider_info
            )
            for new_provider_info in self.new_provider_infos
        ]

    def run_scenario_with_new_provider_info(
        self, ciphertext_writer, generation_scenario, materials_manager, new_provider_info
    ):
        """Run with tampering for a specific new provider info value"""
        tampering_materials_manager = ProviderInfoChangingCryptoMaterialsManager(materials_manager, new_provider_info)
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

    wrapped_cmm = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsManager))
    new_provider_info = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __init__(self, materials_manager, new_provider_info):
        """Create a new CMM that wraps a the given CMM."""
        self.wrapped_cmm = materials_manager
        self.new_provider_info = new_provider_info

    def get_encryption_materials(self, request):
        """
        Request materials from the wrapped CMM, and then change the provider info
        on each EDK.
        """
        result = self.wrapped_cmm.get_encryption_materials(request)
        for encrypted_data_key in result.encrypted_data_keys:
            encrypted_data_key.key_provider.key_info = self.new_provider_info
        return result

    def decrypt_materials(self, request):
        """Thunks to the wrapped CMM"""
        return self.wrapped_cmm.decrypt_materials(request)


BITS_PER_BYTE = 8


class TruncateTamperingMethod(TamperingMethod):
    """Tampering method that truncates a good message at every byte (except zero)."""

    # pylint: disable=R0201
    def run_scenario_with_tampering(self, ciphertext_writer, generation_scenario, _plaintext_uri):
        """
        Run a given scenario, tampering with the input or the result.

        return: a list of (ciphertext, result) pairs.
        """
        ciphertext_to_decrypt = generation_scenario.encryption_scenario.run()
        return [
            generation_scenario.decryption_test_scenario_pair(
                ciphertext_writer,
                TruncateTamperingMethod.flip_bit(ciphertext_to_decrypt, bit),
                MessageDecryptionTestResult.expect_error("Bit {} flipped".format(bit)),
            )
            for bit in range(0, len(ciphertext_to_decrypt) * BITS_PER_BYTE)
        ]

    @classmethod
    def flip_bit(cls, ciphertext, bit):
        """Flip only the given bit in the given ciphertext"""
        byte_index, bit_index = divmod(bit, BITS_PER_BYTE)
        result = bytearray(ciphertext)
        result[byte_index] ^= 1 << (BITS_PER_BYTE - bit_index - 1)
        return bytes(result)


class MutateTamperingMethod(TamperingMethod):
    """Tampering method that produces a message with a single bit flipped, for every possible bit."""

    # pylint: disable=R0201
    def run_scenario_with_tampering(self, ciphertext_writer, generation_scenario, _plaintext_uri):
        """
        Run a given scenario, tampering with the input or the result.

        return: a list of (ciphertext, result) pairs.
        """
        ciphertext_to_decrypt = generation_scenario.encryption_scenario.run()
        return [
            generation_scenario.decryption_test_scenario_pair(
                ciphertext_writer,
                ciphertext_to_decrypt[0:length],
                MessageDecryptionTestResult.expect_error("Truncated at byte {}".format(length)),
            )
            for length in range(1, len(ciphertext_to_decrypt))
        ]


class HalfSigningTamperingMethod(TamperingMethod):
    """Tampering method that changes the provider info on all EDKs."""

    # pylint: disable=R0201
    def run_scenario_with_tampering(self, ciphertext_writer, generation_scenario, _plaintext_uri):
        """
        Run a given scenario, tampering with the input or the result.

        return: a list of (ciphertext, result) pairs.
        """
        tampering_materials_manager = HalfSigningCryptoMaterialsManager(
            generation_scenario.encryption_scenario.master_key_provider_fn()
        )
        ciphertext_to_decrypt = generation_scenario.encryption_scenario.run(tampering_materials_manager)
        expected_result = MessageDecryptionTestResult.expect_error(
            "Unsigned message using a data key with a public key"
        )
        return [
            generation_scenario.decryption_test_scenario_pair(ciphertext_writer, ciphertext_to_decrypt, expected_result)
        ]


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
    :param decryption_master_key_specs: Iterable of master key specifications
    :type decryption_master_key_specs: iterable of :class:`MasterKeySpec`
    :param Callable decryption_master_key_provider_fn:
    :param result:
    :param bool keyrings: True if should encrypt with keyring interfaces; False otherwise
    """

    encryption_scenario = attr.ib(validator=attr.validators.instance_of(MessageEncryptionTestScenario))
    tampering_method = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(TamperingMethod)))
    decryption_method = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(DecryptionMethod)))
    decryption_master_key_specs = attr.ib(validator=iterable_validator(list, MasterKeySpec))
    decryption_master_key_provider_fn = attr.ib(validator=attr.validators.is_callable())
    result = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(MessageDecryptionTestResult)))
    keyrings = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    def from_scenario(cls, scenario, keys, plaintexts, keyrings, keys_uri):
        """Load from a scenario specification.

        :param dict scenario: Scenario specification JSON
        :param KeysManifest keys: Loaded keys
        :param dict plaintexts: Mapping of plaintext names to plaintext values
        :param bool keyrings: True if should encrypt with keyring interfaces; False otherwise
        :param string keys_uri: Filepath to keys manifest. Used by MPL TestVector keyring constructor.
        :return: Loaded test scenario
        :rtype: MessageDecryptionTestScenarioGenerator
        """
        encryption_scenario_spec = scenario["encryption-scenario"]
        encryption_scenario = MessageEncryptionTestScenario.from_scenario(
            encryption_scenario_spec,
            keys,
            plaintexts,
            keyrings,
            keys_uri,
        )
        tampering = scenario.get("tampering")
        tampering_method = TamperingMethod.from_tampering_spec(tampering)
        decryption_method_spec = scenario.get("decryption-method")
        decryption_method = DecryptionMethod(decryption_method_spec) if decryption_method_spec else None
        if "decryption-master-keys" in scenario:
            decryption_master_key_specs = [
                MasterKeySpec.from_scenario(spec) for spec in scenario["decryption-master-keys"]
            ]

            # if keyrings:
            #     decryption_master_key_specs = [
            #         KeyringSpec.from_scenario(spec) for spec in scenario["decryption-master-keys"]
            #     ]
            # else:
            #     decryption_master_key_specs = [
            #         MasterKeySpec.from_scenario(spec) for spec in scenario["decryption-master-keys"]
            #     ]

            def decryption_master_key_provider_fn():
                if keyrings:
                    return keyring_from_master_key_specs(keys_uri, decryption_master_key_specs)
                else:
                    return master_key_provider_from_master_key_specs(keys, decryption_master_key_specs)

        else:
            decryption_master_key_specs = encryption_scenario.master_key_specs
            decryption_master_key_provider_fn = encryption_scenario.master_key_provider_fn
        result_spec = scenario.get("result")
        result = MessageDecryptionTestResult.from_result_spec(result_spec, None) if result_spec else None

        return cls(
            encryption_scenario=encryption_scenario,
            tampering_method=tampering_method,
            decryption_method=decryption_method,
            decryption_master_key_specs=decryption_master_key_specs,
            decryption_master_key_provider_fn=decryption_master_key_provider_fn,
            result=result,
            keyrings=keyrings,
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

    def decryption_test_scenario_pair(self, ciphertext_writer, ciphertext_to_decrypt, expected_result):
        """Create a new (name, decryption scenario) pair"""
        ciphertext_name = str(uuid.uuid4())
        ciphertext_uri = ciphertext_writer(ciphertext_name, ciphertext_to_decrypt)

        return (
            ciphertext_name,
            MessageDecryptionTestScenario(
                ciphertext_uri=ciphertext_uri,
                ciphertext=ciphertext_to_decrypt,
                master_key_specs=self.decryption_master_key_specs,
                master_key_provider_fn=self.decryption_master_key_provider_fn,
                decryption_method=self.decryption_method,
                result=expected_result,
                keyrings=self.keyrings,
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
    :param bool keyrings: True if should encrypt with keyring interfaces; False otherwise
    """

    version = attr.ib(validator=membership_validator(SUPPORTED_VERSIONS))
    keys = attr.ib(validator=attr.validators.instance_of(KeysManifest))
    plaintexts = attr.ib(validator=dictionary_validator(six.string_types, six.binary_type))
    tests = attr.ib(validator=dictionary_validator(six.string_types, MessageDecryptionTestScenarioGenerator))
    keyrings = attr.ib(validator=attr.validators.instance_of(bool))
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
    def from_file(cls, input_file, keyrings):
        # type: (IO) -> MessageDecryptionGenerationManifest
        """Load from a file containing a full message encrypt manifest.

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
                tests[name] = MessageDecryptionTestScenarioGenerator.from_scenario(
                    scenario=scenario, keys=keys, plaintexts=plaintexts, keyrings=keyrings, keys_uri=keys_abs_path,
                )
            except NotImplementedError:
                continue
        return cls(version=raw_manifest["manifest"]["version"], keys=keys, plaintexts=plaintexts, tests=tests, keyrings=keyrings)

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
