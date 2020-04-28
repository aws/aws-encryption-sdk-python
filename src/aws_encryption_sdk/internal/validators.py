# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Common ``attrs`` validators."""
import attr  # only used by mypy, so pylint: disable=unused-import
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


# The unused-argument check is disabled because
# this function MUST match the function signature
# for attrs validators.
def value_is_not_a_string(instance, attribute, value):  # pylint: disable=unused-argument
    # type: (Any, attr.Attribute, Any) -> None
    """Technically a string is an iterable containing strings.

    This validator lets you accept other iterators but not strings.
    """
    if isinstance(value, six.string_types):
        raise TypeError("'{}' must not a string".format(attribute.name))
