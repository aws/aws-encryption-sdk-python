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
import os
import struct
from binascii import unhexlify

import six
from aws_encryption_sdk.identifiers import AlgorithmSuite

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Callable, Iterable, Type, Union  # noqa pylint: disable=unused-import
    from awses_test_vectors.internal.mypy_types import MANIFEST_VERSION  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def _file_exists_error():
    # type: () -> Type[Exception]
    """Return the appropriate error that ``os.makedirs`` returns if the output directory
    already exists.
    """
    if six.PY3:
        return FileExistsError
    return OSError


def makedir_if_not_exist(dir_name):
    # type: (str) -> None
    """"""
    try:
        os.makedirs(dir_name)
    except _file_exists_error():
        # os.makedirs(... exist_ok=True) does not work in 2.7
        pass


def validate_manifest_type(type_name, manifest_version, supported_versions):
    # type: (str, MANIFEST_VERSION, Iterable[int]) -> None
    """"""
    try:
        if manifest_version["type"] != type_name:
            raise ValueError(
                'Invalid manifest type: "{actual}" != "{expected}"'.format(
                    actual=manifest_version["type"], expected=type_name
                )
            )
        if manifest_version["version"] not in supported_versions:
            raise ValueError(
                'Invalid manifest version: "{actual}" not in "{supported}"'.format(
                    actual=manifest_version["version"], supported=supported_versions
                )
            )
    except KeyError:
        raise ValueError("Invalid manifest format")


def membership_validator(allowed):
    # type: (Iterable[Any]) -> Callable
    """``attrs`` validator to perform check that attribute value is in a set of allowed values."""

    def _validate_membership(instance, attribute, value):
        # pylint: disable=unused-argument
        """"""
        if value not in allowed:
            raise ValueError(
                'Unknown "{name}" value "{actual}" not in {expected}'.format(
                    name=attribute.name, actual=value, expected=allowed
                )
            )

    return _validate_membership


def dictionary_validator(key_type, value_type):
    # type: (Type, Type) -> Callable
    """``attrs`` validator to perform deep type checking of dictionaries."""

    def _validate_dictionary(instance, attribute, value):
        # pylint: disable=unused-argument
        """Validate that a dictionary is structured as expected.

        :raises TypeError: if ``value`` is not a dictionary
        :raises TypeError: if ``value`` keys are not all of ``key_type`` type
        :raises TypeError: if ``value`` values are not all of ``value_type`` type
        """
        if not isinstance(value, dict):
            raise TypeError('"{}" must be a dictionary'.format(attribute.name))

        for key, data in value.items():
            if not isinstance(key, key_type):
                raise TypeError(
                    '"{name}" dictionary keys must be of type "{type}"'.format(name=attribute.name, type=key_type)
                )

            if not isinstance(data, value_type):
                raise TypeError(
                    '"{name}" dictionary values must be of type "{type}"'.format(name=attribute.name, type=value_type)
                )

    return _validate_dictionary


def iterable_validator(iterable_type, member_type):
    # type: (Type, Type) -> Callable
    """``attrs`` validator to perform deep type checking of iterables."""

    def _validate_tuple(instance, attribute, value):
        # pylint: disable=unused-argument
        """Validate that a dictionary is structured as expected.

        :raises TypeError: if ``value`` is not of ``iterable_type`` type
        :raises TypeError: if ``value`` members are not all of ``member_type`` type
        """
        if not isinstance(value, iterable_type):
            raise TypeError('"{name}" must be a {type}'.format(name=attribute.name, type=iterable_type))

        for member in value:
            if not isinstance(member, member_type):
                raise TypeError(
                    '"{name}" members must all be of type "{type}"'.format(name=attribute.name, type=member_type)
                )

    return _validate_tuple


def algorithm_suite_from_string_id(string_id):
    # type: (str) -> AlgorithmSuite
    """"""
    bytes_id = unhexlify(string_id)
    (numeric_id,) = struct.unpack(">H", bytes_id)
    return AlgorithmSuite.get_by_id(numeric_id)


def file_writer(parent_dir):
    # type: (str) -> Callable
    """Return a caller that will write the requested named data to a file and return
    a URI locating the written data.

    :param str parent_dir: Directory in which to write all files
    :return: URI-returning named data writer
    :rtype: callable
    """
    # Abstracted like this because we want to support reading from and writing to S3 in the future.

    makedir_if_not_exist(parent_dir)

    def _write_file(name, data):
        # type: (str, bytes) -> str
        """Write the data to a file on disk in ``parent_dir`` and named ``name``.

        :param str name: Filename to write inside ``parent_dir``
        :param bytes data: Data to write to file
        :return: File URI locating the written file relative to ``parent_dir``'s parent directory
        :rtype: str
        """
        file_uri = "file://{dir}/{name}".format(dir=os.path.basename(parent_dir), name=name)
        file_path = os.path.join(parent_dir, name)
        with open(file_path, "wb") as target:
            target.write(data)
        return file_uri

    return _write_file
