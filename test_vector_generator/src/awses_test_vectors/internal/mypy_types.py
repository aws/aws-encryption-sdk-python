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
MyPy types for use in AWS Encryption SDK test vector handlers.
"""
# mypy types confuse pylint: disable=invalid-name
from attr import Attribute

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import (  # noqa pylint: disable=unused-import
        Any,
        Callable,
        Dict,
        IO,
        Iterable,
        Optional,
        Tuple,
        Type,
        Union,
    )

    ISINSTANCE = Union[type, Tuple[Union[type, Tuple[Any, ...]], ...]]

    MANIFEST_VERSION = Dict[str, Union[str, int]]

    AWS_KMS_KEY_SPEC = Dict[str, Union[bool, str]]
    MANUAL_KEY_SPEC = Dict[str, Union[bool, str, int, Iterable[str]]]
    KEY_SPEC = Union[AWS_KMS_KEY_SPEC, MANUAL_KEY_SPEC]
    KEYS_MANIFEST = Dict[str, Union[MANIFEST_VERSION, Iterable[KEY_SPEC]]]

    ENCRYPTION_CONTEXT = Dict[str, str]
    PLAINTEXTS_SPEC = Dict[str, int]
    MASTER_KEY_SPEC = Dict[str, str]
    ENCRYPT_SCENARIO_SPEC = Dict[str, Union[str, int, ENCRYPTION_CONTEXT, Iterable[MASTER_KEY_SPEC]]]
    FULL_MESSAGE_ENCRYPT_MANIFEST = Dict[
        str, Union[MANIFEST_VERSION, str, PLAINTEXTS_SPEC, Iterable[ENCRYPT_SCENARIO_SPEC]]
    ]

    CLIENT_VERSION = Dict[str, str]
    DECRYPT_SCENARIO_SPEC = Dict[str, Union[str, Iterable[MASTER_KEY_SPEC]]]
    FULL_MESSAGE_DECRYPT_MANIFEST = Dict[
        str, Union[MANIFEST_VERSION, CLIENT_VERSION, str, Iterable[DECRYPT_SCENARIO_SPEC]]
    ]
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass
