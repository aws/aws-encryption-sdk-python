# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Contains logic for checking ESDK and Python Version"""
import sys
import warnings

DEPRECATION_DATE_MAP = {"1.x": "2022-06-30", "2.x": "2022-07-01"}


def _warn_deprecated_python():
    """Template for deprecation of Python warning."""
    deprecated_versions = {
        (2, 7): {"date": DEPRECATION_DATE_MAP["2.x"]},
        (3, 4): {"date": DEPRECATION_DATE_MAP["2.x"]},
        (3, 5): {"date": "2021-11-10"},
    }
    py_version = (sys.version_info.major, sys.version_info.minor)
    minimum_version = (3, 6)

    if py_version in deprecated_versions:
        params = deprecated_versions[py_version]
        warning = (
            "aws-encryption-sdk will no longer support Python {}.{} "
            "starting {}. To continue receiving service updates, "
            "bug fixes, and security updates please upgrade to Python {}.{} or "
            "later. For more information, see SUPPORT_POLICY.rst: "
            "https://github.com/aws/aws-encryption-sdk-python/blob/master/SUPPORT_POLICY.rst"
        ).format(py_version[0], py_version[1], params["date"], minimum_version[0], minimum_version[1])
        warnings.warn(warning, DeprecationWarning)
