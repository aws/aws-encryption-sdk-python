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

import attr
import aws_encryption_sdk
import six

from awses_test_vectors.manifests.master_key import MasterKeySpec
from awses_test_vectors.util import dictionary_validator, iterable_validator, validate_manifest_type

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Callable, Dict, IO  # noqa pylint: disable=unused-import
    from awses_test_vectors.mypy_types import (  # noqa pylint: disable=unused-import
        DECRYPT_SCENARIO_SPEC,
        FULL_MESSAGE_DECRYPT_MANIFEST,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

CLIENT_NAME = "aws/aws-encryption-sdk-python"
CURRENT_VERSION = 1
SUPPORTED_VERSIONS = (1,)


@attr.s
class DecryptTestScenario(object):
    """"""

    # pylint: disable=too-few-public-methods

    plaintext_uri = attr.ib(validator=attr.validators.instance_of(six.string_types))
    plaintext = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    ciphertext_uri = attr.ib(validator=attr.validators.instance_of(six.string_types))
    ciphertext = attr.ib(validator=attr.validators.instance_of(six.binary_type))
    master_keys = attr.ib(validator=iterable_validator(list, MasterKeySpec))
    description = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types))
    )

    @classmethod
    def from_scenario(cls, scenario, plaintext_reader, ciphertext_reader):
        # type: (DECRYPT_SCENARIO_SPEC, Callable, Callable) -> DecryptTestScenario
        """"""
        return cls(
            plaintext_uri=scenario["plaintext"],
            plaintext=plaintext_reader(scenario["plaintext"]),
            ciphertext_uri=scenario["ciphertext"],
            ciphertext=ciphertext_reader(scenario["ciphertext"]),
            master_keys=[MasterKeySpec.from_scenario_spec(spec) for spec in scenario["master-keys"]],
            description=scenario.get("description"),
        )

    @property
    def scenario_spec(self):
        # type: () -> DECRYPT_SCENARIO_SPEC
        """"""
        spec = {
            "plaintext": self.plaintext_uri,
            "ciphertext": self.ciphertext_uri,
            "master-keys": [spec.scenario_spec for spec in self.master_keys],
        }
        if self.description is not None:
            spec["description"] = self.description
        return spec


@attr.s
class DecryptMessageManifest(object):
    """"""

    keys_uri = attr.ib(validator=attr.validators.instance_of(six.string_types))
    parent_dir = attr.ib(validator=attr.validators.instance_of(six.string_types))
    test_scenarios = attr.ib(
        default=attr.Factory(dict), validator=dictionary_validator(six.string_types, DecryptTestScenario)
    )
    version = attr.ib(default=CURRENT_VERSION, validator=attr.validators.instance_of(int))
    type_name = "awses-decrypt"

    @property
    def manifest_spec(self):
        # type: () -> FULL_MESSAGE_DECRYPT_MANIFEST
        """"""
        return {
            "manifest": {"type": self.type_name, "version": self.version},
            "client": {"name": CLIENT_NAME, "version": aws_encryption_sdk.__version__},
            "keys": self.keys_uri,
            "tests": {name: spec.scenario_spec for name, spec in self.test_scenarios.items()},
        }

    @classmethod
    def from_file(cls, input_file):
        # type: (IO) -> DecryptMessageManifest
        """"""
        raw_manifest = json.load(input_file)
        validate_manifest_type(
            type_name=cls.type_name, manifest_version=raw_manifest["manifest"], supported_versions=SUPPORTED_VERSIONS
        )

        parent_dir = os.path.abspath(os.path.dirname(input_file.name))
