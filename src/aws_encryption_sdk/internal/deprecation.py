# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Module containing utilities for deprecated components."""
import warnings
import functools


def deprecated(reason):
    """
    Decorator to apply to classes to emit deprecation warnings.
    """
    def decorator(cls):
        # If class does not define init,
        # its default init it Python's object.__init__,
        # which only takes self as an arg
        # and cannot take any args or kwargs.
        if cls.__init__ is object.__init__:
            # Make a new init that just emits this deprecation warning.
            def new_init(self):  # pylint: disable=unused-argument
                warnings.warn(f"{cls.__name__} is deprecated: {reason}",
                              category=DeprecationWarning, stacklevel=2)
        else:
            original_init = cls.__init__

            # Wrap the original init method with a deprecation warning.
            @functools.wraps(cls.__init__)
            def new_init(self, *args, **kwargs):
                warnings.warn(f"{cls.__name__} is deprecated: {reason}",
                              category=DeprecationWarning, stacklevel=2)
                original_init(self, *args, **kwargs)

        cls.__init__ = new_init
        return cls

    return decorator
