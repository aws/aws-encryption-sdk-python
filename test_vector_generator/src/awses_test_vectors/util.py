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
"""Utility functions for use by test vector handlers."""
from binascii import unhexlify
import struct

from aws_encryption_sdk.identifiers import AlgorithmSuite

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Iterable, Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def validate_manifest_type(type_name, manifest, supported_versions):
    # type: (str, Dict[str, Union[str, int]], Iterable[int]) -> None
    """"""
    manifest_member = manifest['manifest']
    try:
        if manifest_member['type'] != type_name:
            raise ValueError('Invalid manifest type: "{actual}" != "{expected}"'.format(
                actual=manifest_member['type'],
                expected=type_name
            ))
        if manifest_member['version'] not in supported_versions:
            raise ValueError(
                'Invalid manifest version: "{actual}" not in "{supported}"'.format(
                    actual=manifest_member['version'],
                    supported=supported_versions
                )
            )
    except KeyError:
        raise ValueError('Invalid manifest format')


def membership_validator(value_name, allowed):
    """"""

    def _validate_membership(instance, attribute, value):
        """"""
        if value not in allowed:
            raise ValueError('Unknown {name} "{actual}" not in {expected}'.format(
                name=value_name,
                actual=value,
                expected=allowed
            ))

    return _validate_membership


def algorithm_suite_from_string_id(string_id):
    # type: (str) -> AlgorithmSuite
    """"""
    bytes_id = unhexlify(string_id)
    (numeric_id,) = struct.unpack('>H', bytes_id)
    return AlgorithmSuite.get_by_id(numeric_id)
