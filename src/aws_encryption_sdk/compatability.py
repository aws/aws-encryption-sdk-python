# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
        (3, 7): {"date": "2024-03-04"},
    }
    py_version = (sys.version_info.major, sys.version_info.minor)
    minimum_version = (3, 8)

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
