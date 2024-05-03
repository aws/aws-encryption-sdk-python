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
AWS Encryption SDK Decrypt Message manifest handler.

Described in AWS Crypto Tools Test Vector Framework feature #0003 AWS Encryption SDK Decrypt Message.
"""
import json
import os
from enum import Enum

import attr
import aws_encryption_sdk
import pytest
import six
from aws_encryption_sdk.identifiers import CommitmentPolicy

from awses_test_vectors.internal.defaults import ENCODING
from awses_test_vectors.internal.util import (
    dictionary_validator,
    file_reader,
    iterable_validator,
    validate_manifest_type,
)
from awses_test_vectors.manifests.keys import KeysManifest
from awses_test_vectors.manifests.master_key import MasterKeySpec, master_key_provider_from_master_key_specs

try:
    from awses_test_vectors.manifests.mpl_keyring import KeyringSpec, keyring_from_master_key_specs
    from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
    from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
    from aws_cryptographic_materialproviders.mpl.references import ICryptographicMaterialsManager
    from aws_cryptographic_materialproviders.mpl.models import (
        CreateDefaultCryptographicMaterialsManagerInput,
        CreateRequiredEncryptionContextCMMInput,
    )

    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False


try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import IO, Callable, Dict, Iterable, Optional  # noqa pylint: disable=unused-import

    from awses_test_vectors.internal.mypy_types import (  # noqa pylint: disable=unused-import
        DECRYPT_SCENARIO_SPEC,
        FULL_MESSAGE_DECRYPT_MANIFEST,
        MASTER_KEY_SPEC,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

CLIENT_NAME = "aws/aws-encryption-sdk-python"
CURRENT_VERSION = 2
SUPPORTED_VERSIONS = (2, 4,)


@attr.s(init=False)
class MessageDecryptionTestOutputResultMatcher(object):
    """
    Matcher asserting that decryption succeeds and produces
    a given plaintext.
    """

    plaintext_uri = attr.ib(validator=attr.validators.instance_of(six.string_types))
    plaintext = attr.ib(validator=attr.validators.instance_of(six.binary_type))

    def __init__(
        self,
        plaintext_uri,  # type: str
        plaintext,  # type: bytes
    ):
        """Create a matcher that asserts the given plaintext is produced."""
        self.plaintext_uri = plaintext_uri
        self.plaintext = plaintext
        attr.validate(self)

    @classmethod
    def from_matcher_spec(
        cls,
        spec,
        plaintext_reader,  # type: Callable[[str], bytes]
    ):
        """Load from a matcher specification"""
        plaintext_uri = spec["plaintext"]
        plaintext = plaintext_reader(plaintext_uri)
        return cls(plaintext_uri, plaintext)

    @property
    def matcher_spec(self):
        """Build a matcher specification for this matcher"""
        return {"plaintext": self.plaintext_uri}

    def match(self, name, decrypt_fn):
        """Assert that the given decrypt closure behaves as expected."""
        try:
            plaintext, _header = decrypt_fn()
            if plaintext != self.plaintext:
                raise ValueError("Decrypted plaintext does not match expected value for scenario '{}'".format(name))
        except BaseException:
            raise RuntimeError("Decryption did not succeed as expected for scenario '{}'".format(name))


@attr.s
class MessageDecryptionTestErrorResultMatcher(object):
    """Matcher asserting that decryption fails."""

    error_description = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def from_matcher_spec(cls, spec, plaintext_reader):  # pylint: disable=unused-argument
        """Load from a matcher specification"""
        error_description = spec["error-description"]
        return cls(error_description)

    @property
    def matcher_spec(self):
        """Build a matcher specification for this matcher"""
        return {"error-description": self.error_description}

    def match(self, name, decrypt_fn):
        """Assert that the given decrypt closure behaves as expected."""
        try:
            # The ESDK implementations are not consistent in the types of errors they produce
            # or the exact error messages they use. The most important thing to test is that decryption
            # fails in some way, and hence the overly-broad implicit try/catch here.
            with pytest.raises(Exception):
                decrypt_fn()
        except BaseException:
            # Translate the exception just to attach context.
            raise RuntimeError(
                "Decryption did not fail as expected ({}) for scenario '{}'".format(self.error_description, name)
            )


@attr.s
class MessageDecryptionTestResult(object):
    """
    Data class representing the expected result of a test scenario.
    Currently this is either "output", specifying the expected plaintext,
    or "error", specifying why decryption must fail.
    """

    MATCHER_CLASS_FOR_TAG = {
        "output": MessageDecryptionTestOutputResultMatcher,
        "error": MessageDecryptionTestErrorResultMatcher,
    }

    matcher_tag = attr.ib(validator=attr.validators.instance_of(six.string_types))
    matcher = attr.ib(validator=attr.validators.instance_of(object))

    @classmethod
    def from_result_spec(
        cls,
        spec,
        plaintext_reader,  # type: Callable[[str], bytes]
    ):
        """Load from a result specification"""
        ((matcher_tag, matcher_spec),) = spec.items()
        matcher = cls.MATCHER_CLASS_FOR_TAG[matcher_tag].from_matcher_spec(matcher_spec, plaintext_reader)
        return cls(matcher_tag, matcher)

    @classmethod
    def expect_output(cls, plaintext_uri, plaintext):
        """Build a result that expects the given plaintext."""
        return cls("output", MessageDecryptionTestOutputResultMatcher(plaintext_uri, plaintext))

    @classmethod
    def expect_error(cls, error_description):
        """Build a result that expects failure for the given reason."""
        return cls("error", MessageDecryptionTestErrorResultMatcher(error_description))

    @property
    def result_spec(self):
        """Build a result specification for this result"""
        return {self.matcher_tag: self.matcher.matcher_spec}


class DecryptionMethod(Enum):
    """Enumeration of decryption methods."""

    UNSIGNED_ONLY_STREAM = "streaming-unsigned-only"


@attr.s(init=False)
class MessageDecryptionTestScenario(object):
    # pylint: disable=too-many-arguments,too-many-instance-attributes
    """Data class for a single full message decrypt test scenario.

    Handles serialization and deserialization to and from manifest specs.

    :param str ciphertext_uri: URI locating ciphertext data
    :param bytes ciphertext: Binary ciphertext data
    :param boolean must_fail: Whether decryption is expected to fail
    :param master_key_specs: Iterable of master key specifications
    :type master_key_specs: iterable of :class:`MasterKeySpec`
    :param Callable master_key_provider_fn:
    :param bool keyrings: True if should decrypt with keyring interfaces; False otherwise
    :param str cmm_type: `cmm` from test vector manifest; "Default" if not specified
    :param str encryption_context: Any encryption context to validate on decrypt if using
        keyrings AND the required encryption context CMM
    :param str description: Description of test scenario (optional)
    """

    # pylint: disable=too-few-public-methods

    ciphertext_uri = attr.ib(validator=attr.validators.instance_of(six.string_types))
    ciphertext = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    master_key_specs = attr.ib(validator=iterable_validator(list, MasterKeySpec))
    master_key_provider_fn = attr.ib(validator=attr.validators.is_callable())
    result = attr.ib(validator=attr.validators.instance_of(MessageDecryptionTestResult))
    keyrings = attr.ib(validator=attr.validators.instance_of(bool))
    cmm_type = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)))
    decryption_method = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(DecryptionMethod))
    )
    description = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types))
    )

    def __init__(
        self,
        ciphertext_uri,  # type: str
        ciphertext,  # type: bytes
        result,  # type: MessageDecryptionTestResult
        master_key_specs,  # type: Iterable[MasterKeySpec]
        master_key_provider_fn,  # type: Callable
        keyrings,  # type: bool
        cmm_type,  # type: str
        encryption_context,  # type: Dict[str, str]
        decryption_method=None,  # type: Optional[DecryptionMethod]
        description=None,  # type: Optional[str]
    ):  # noqa=D107
        # type: (...) -> None
        """Set initial values for the test scenario."""
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.ciphertext_uri = ciphertext_uri
        self.ciphertext = ciphertext
        self.result = result
        self.master_key_specs = master_key_specs
        self.master_key_provider_fn = master_key_provider_fn
        self.keyrings = keyrings
        self.cmm_type = cmm_type
        self.encryption_context = encryption_context
        self.decryption_method = decryption_method
        self.description = description
        attr.validate(self)

    @classmethod
    def from_scenario(
        cls,
        scenario,  # type: DECRYPT_SCENARIO_SPEC
        plaintext_reader,  # type: Callable[[str], bytes]
        ciphertext_reader,  # type: Callable[[str], bytes]
        keys,  # type: KeysManifest
        keyrings,  # type: bool
        keys_uri,  # type: str
    ):
        # pylint: disable=too-many-locals
        # type: (...) -> MessageDecryptionTestScenario
        """Load from a scenario specification.

        :param dict scenario: Scenario specification JSON
        :param plaintext_reader: URI-handling data reader for reading plaintext
        :param ciphertext_reader: URI-handling data reader for reading ciphertext
        :param KeysManifest keys: Loaded keys
        :return: Loaded test scenario
        :rtype: MessageDecryptionTestScenario
        """
        raw_master_key_specs = scenario["master-keys"]  # type: Iterable[MASTER_KEY_SPEC]
        if keyrings:
            master_key_specs = [
                KeyringSpec.from_scenario(spec) for spec in raw_master_key_specs
            ]
        else:
            master_key_specs = [
                MasterKeySpec.from_scenario(spec) for spec in raw_master_key_specs \
                    if spec["type"] != "aws-kms-hierarchy"
            ]

        def master_key_provider_fn():
            if keyrings:
                return keyring_from_master_key_specs(keys_uri, master_key_specs, "decrypt")
            return master_key_provider_from_master_key_specs(keys, master_key_specs)

        decryption_method_spec = scenario.get("decryption-method")
        decryption_method = DecryptionMethod(decryption_method_spec) if decryption_method_spec else None
        result_spec = scenario["result"]
        result = MessageDecryptionTestResult.from_result_spec(result_spec, plaintext_reader)


        if "encryption-context" in scenario:
            encryption_context = scenario["encryption-context"]
        else:
            encryption_context = {}

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
                raise ValueError("Unrecognized cmm_type: " + scenario["cmm"])
        else:
            # If unspecified, set "Default" as the default
            cmm_type = "Default"

        # If this scenario does not have any key providers,
        # do not create a scenario.
        # Caller logic should expect `None` to mean "no scenario".
        if master_key_provider_fn() is None:
            return None

        return cls(
            ciphertext_uri=scenario["ciphertext"],
            ciphertext=ciphertext_reader(scenario["ciphertext"]),
            master_key_specs=master_key_specs,
            master_key_provider_fn=master_key_provider_fn,
            result=result,
            keyrings=keyrings,
            encryption_context=encryption_context,
            cmm_type=cmm_type,
            decryption_method=decryption_method,
            description=scenario.get("description"),
        )

    @property
    def scenario_spec(self):
        # type: () -> DECRYPT_SCENARIO_SPEC
        """Build a scenario specification describing this test scenario.

        :return: Scenario specification JSON
        :rtype: dict
        """
        spec = {
            "ciphertext": self.ciphertext_uri,
            "master-keys": [spec.scenario_spec for spec in self.master_key_specs],
            "result": self.result.result_spec,
        }
        if self.decryption_method is not None:
            spec["decryption-method"] = self.decryption_method.value
        if self.description is not None:
            spec["description"] = self.description
        spec["cmm"] = self.cmm_type
        spec["encryption-context"] = self.encryption_context
        
        return spec

    def _one_shot_decrypt(self):
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
        if self.cmm_type == "Default":
            if self.keyrings:
                return client.decrypt(source=self.ciphertext, keyring=self.master_key_provider_fn())
            return client.decrypt(source=self.ciphertext, key_provider=self.master_key_provider_fn())
        if self.cmm_type == "RequiredEncryptionContext":
            # We need to make a custom CMM and pass it into the client
            if not self.keyrings:
                raise ValueError("Must provide keyrings arg to use RequiredEncryptionContext")
            if not _HAS_MPL:
                raise ValueError("Must install the aws-cryptographic-material-providers library"
                                 "to use RequiredEncryptionContext")

            mpl: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
                config=MaterialProvidersConfig()
            )

            underlying_cmm: ICryptographicMaterialsManager = \
                mpl.create_default_cryptographic_materials_manager(
                    CreateDefaultCryptographicMaterialsManagerInput(
                        keyring=self.master_key_provider_fn()
                    )
                )

            required_ec_cmm: ICryptographicMaterialsManager = \
                mpl.create_required_encryption_context_cmm(
                    CreateRequiredEncryptionContextCMMInput(
                        # Currently, the test vector manifest assumes these
                        # are the only required encryption context keys for any message.
                        # If this assumption changes, this logic must be augmented.
                        required_encryption_context_keys=["key1", "key2"],
                        underlying_cmm=underlying_cmm,
                    )
                )

            return client.decrypt(
                source=self.ciphertext,
                materials_manager=required_ec_cmm,
                encryption_context=self.encryption_context,
            )

        # If the cmm type was not in if/elif above, raise error
        raise ValueError(f"Unrecognized cmm_type: {self.cmm_type}")

    def _streaming_decrypt(self):
        result = bytearray()
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

        kwargs = {
            "source": self.ciphertext,
            "mode": "d"
        }
        if self.cmm_type == "Default":
            if self.keyrings:
                kwargs["keyring"] = self.master_key_provider_fn()
            else:
                kwargs["key_provider"] = self.master_key_provider_fn()
        elif self.cmm_type == "RequiredEncryptionContext":
            # We need to make a custom CMM and pass it into the client
            if not self.keyrings:
                raise ValueError("Must provide keyrings arg to use RequiredEncryptionContext")
            if not _HAS_MPL:
                raise ValueError("Must install the aws-cryptographic-material-providers library"
                                 "to use RequiredEncryptionContext")

            mpl: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
                config=MaterialProvidersConfig()
            )

            underlying_cmm: ICryptographicMaterialsManager = \
                mpl.create_default_cryptographic_materials_manager(
                    CreateDefaultCryptographicMaterialsManagerInput(
                        keyring=self.master_key_provider_fn()
                    )
                )

            required_ec_cmm: ICryptographicMaterialsManager = \
                mpl.create_required_encryption_context_cmm(
                    CreateRequiredEncryptionContextCMMInput(
                        # Currently, the test vector manifest assumes these
                        # are the only required encryption context keys for any message.
                        # If this assumption changes, this logic must be augmented.
                        required_encryption_context_keys=["key1", "key2"],
                        underlying_cmm=underlying_cmm,
                    )
                )

            kwargs["materials_manager"] = required_ec_cmm
            kwargs["encryption_context"] = self.encryption_context
        else:
            raise ValueError(f"Unrecognized cmm_type: {self.cmm_type}")

        with client.stream(**kwargs) as decryptor:
            for chunk in decryptor:
                result.extend(chunk)
            return result, decryptor.header

    def _streaming_decrypt_unsigned(self):
        result = bytearray()
        client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

        stream_kwargs = {
            "source": self.ciphertext,
            "mode": "decrypt-unsigned",
        }

        if self.cmm_type == "Default":
            if self.keyrings:
                stream_kwargs["keyring"] = self.master_key_provider_fn()
            else:
                stream_kwargs["key_provider"] = self.master_key_provider_fn()
        elif self.cmm_type == "RequiredEncryptionContext":
            # We need to make a custom CMM and pass it into the client
            if not self.keyrings:
                raise ValueError("Must provide keyrings arg to use RequiredEncryptionContext")
            if not _HAS_MPL:
                raise ValueError("Must install the aws-cryptographic-material-providers library"
                                 "to use RequiredEncryptionContext")

            mpl: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
                config=MaterialProvidersConfig()
            )

            underlying_cmm: ICryptographicMaterialsManager = \
                mpl.create_default_cryptographic_materials_manager(
                    CreateDefaultCryptographicMaterialsManagerInput(
                        keyring=self.master_key_provider_fn()
                    )
                )

            required_ec_cmm: ICryptographicMaterialsManager = \
                mpl.create_required_encryption_context_cmm(
                    CreateRequiredEncryptionContextCMMInput(
                        # Currently, the test vector manifest assumes these
                        # are the only required encryption context keys for any message.
                        # If this assumption changes, this logic must be augmented.
                        required_encryption_context_keys=["key1", "key2"],
                        underlying_cmm=underlying_cmm,
                    )
                )

            stream_kwargs["materials_manager"] = required_ec_cmm
            stream_kwargs["encryption_context"] = self.encryption_context
        else:
            raise ValueError(f"Unrecognized cmm_type: {self.cmm_type}")

        with client.stream(**stream_kwargs) as decryptor:
            for chunk in decryptor:
                result.extend(chunk)
            return result, decryptor.header

    def run(self, name):
        """Run this test scenario

        :param str name: Descriptive name for this scenario to use in any logging or errors
        """
        if self.decryption_method == DecryptionMethod.UNSIGNED_ONLY_STREAM:
            self.result.matcher.match(name, self._streaming_decrypt_unsigned)
        else:
            self.result.matcher.match(name, self._one_shot_decrypt)
            self.result.matcher.match(name, self._streaming_decrypt)


@attr.s(init=False)
class MessageDecryptionManifest(object):
    # pylint: disable=too-many-arguments
    """AWS Encryption SDK Decrypt Message manifest handler.

    Described in AWS Crypto Tools Test Vector Framework feature #0003 AWS Encryption SDK Decrypt Message.

    :param str keys_uri:
    :param KeysManifest keys:
    :param dict test_scenarios:
    :param int version:
    :param str client_name:
    :param str client_version:
    """

    keys_uri = attr.ib(validator=attr.validators.instance_of(six.string_types))
    keys = attr.ib(validator=attr.validators.instance_of(KeysManifest))
    test_scenarios = attr.ib(
        default=attr.Factory(dict), validator=dictionary_validator(six.string_types, MessageDecryptionTestScenario)
    )
    version = attr.ib(default=CURRENT_VERSION, validator=attr.validators.instance_of(int))
    client_name = attr.ib(default=CLIENT_NAME, validator=attr.validators.instance_of(six.string_types))
    client_version = attr.ib(
        default=aws_encryption_sdk.__version__, validator=attr.validators.instance_of(six.string_types)
    )
    type_name = "awses-decrypt"

    def __init__(
        self,
        keys_uri,  # type: str
        keys,  # type: KeysManifest
        test_scenarios=None,  # type: Optional[Dict[str, MessageDecryptionTestScenario]]
        version=CURRENT_VERSION,  # type: Optional[int]
        client_name=CLIENT_NAME,  # type: Optional[str]
        client_version=aws_encryption_sdk.__version__,  # type: Optional[str]
    ):  # noqa=D107
        # type: (...) -> None
        """Set initial values for the manifest."""
        # Workaround pending resolution of attrs/mypy interaction.
        # https://github.com/python/mypy/issues/2088
        # https://github.com/python-attrs/attrs/issues/215
        self.keys_uri = keys_uri
        self.keys = keys
        self.test_scenarios = test_scenarios
        self.version = version
        self.client_name = client_name
        self.client_version = client_version
        attr.validate(self)

    @property
    def manifest_spec(self):
        # type: () -> FULL_MESSAGE_DECRYPT_MANIFEST
        """Build a full message decrypt manifest describing this manifest.

        :return: Manifest JSON
        :rtype: dict
        """
        manifest_spec = {"type": self.type_name, "version": self.version}
        client_spec = {"name": self.client_name, "version": self.client_version}
        test_specs = {name: spec.scenario_spec for name, spec in self.test_scenarios.items()}
        return {"manifest": manifest_spec, "client": client_spec, "keys": self.keys_uri, "tests": test_specs}

    @classmethod
    def from_file(cls, input_file, keyrings):
        # pylint: disable=too-many-locals
        # type: (IO) -> MessageDecryptionManifest
        """Load from a file containing a full message decrypt manifest.

        :param file input_file: File object for file containing JSON manifest
        :param bool keyrings: True if should decrypt with keyring interfaces; False otherwise
        :return: Loaded manifest
        :rtype: MessageDecryptionManifest
        """
        raw_manifest = json.load(input_file)
        validate_manifest_type(
            type_name=cls.type_name, manifest_version=raw_manifest["manifest"], supported_versions=SUPPORTED_VERSIONS
        )

        parent_dir = os.path.abspath(os.path.dirname(input_file.name))
        root_reader = file_reader(parent_dir)

        version = raw_manifest["manifest"]["version"]  # type: int
        keys_uri = raw_manifest["keys"]  # type: str

        # MPL TestVector keyring needs to know the path to the keys file
        keys_uri = raw_manifest["keys"]
        keys_filename = keys_uri.replace("file://", "")
        keys_abs_path = os.path.join(parent_dir, keys_filename)

        raw_keys_manifest = json.loads(root_reader(keys_uri).decode(ENCODING))
        keys = KeysManifest.from_manifest_spec(raw_keys_manifest)

        client_name = raw_manifest["client"]["name"]  # type: str
        client_version = raw_manifest["client"]["version"]  # type: str
        raw_scenarios = raw_manifest["tests"]  # type: Dict[str, DECRYPT_SCENARIO_SPEC]
        test_scenarios = {
            name: MessageDecryptionTestScenario.from_scenario(
                scenario=scenario,
                plaintext_reader=root_reader,
                ciphertext_reader=root_reader,
                keys=keys,
                keyrings=False,
                keys_uri=keys_abs_path,
            )
            for name, scenario in raw_scenarios.items()
        }
        # If optional keyrings argument is true,
        # also add scenarios to decrypt with keyrings.
        if keyrings:
            keyrings_test_scenarios = {
                name + "-keyring": MessageDecryptionTestScenario.from_scenario(
                    scenario=scenario,
                    plaintext_reader=root_reader,
                    ciphertext_reader=root_reader,
                    keys=keys,
                    keyrings=True,
                    keys_uri=keys_abs_path,
                )
                for name, scenario in raw_scenarios.items()
            }
            # Merge keyring scenarios into test_scenarios
            test_scenarios = {**keyrings_test_scenarios, **test_scenarios}

        # Remove any `None` scenarios from test scenarios.
        # `None` scenarios indicate the loader determined the scenario is invalid.
        # e.g. cmm_type = "RequiredEncryptionContext" with master keys
        for name in list(test_scenarios.keys()):
            if test_scenarios[name] is None:
                del test_scenarios[name]

        return cls(
            keys_uri=keys_uri,
            keys=keys,
            test_scenarios=test_scenarios,
            version=version,
            client_name=client_name,
            client_version=client_version,
        )

    def run(self):
        # () -> None
        """Process all scenarios in this manifest."""
        for name, scenario in self.test_scenarios.items():
            scenario.run(name)
