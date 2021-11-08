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
"""Unit test suite for aws_encryption_sdk.compatability"""
import os
import re
import sys
from typing import Mapping, Optional

import mock
import pytest

from aws_encryption_sdk.compatability import DEPRECATION_DATE_MAP, _warn_deprecated_python

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _parse_support_policy() -> Mapping[str, str]:
    """Parses SUPPORT_POLICY.rst for Major Version Dates

    The code here is strongly tied to the format of SUPPORT_POLICY.rst.
    If the format changes, this logic will need to be refactored as well.

    :rtype Mapping[str, str]
    :return Mapping of keys from DEPRECATION_DATE_MAP to parsed date
    """
    here = os.path.abspath(os.path.dirname(__file__))
    mv_date_line_offset = 3

    def read(*args):
        """Reads complete file contents."""
        return open(os.path.join(here, *args), encoding="utf-8").read()  # pylint: disable=consider-using-with

    def _major_version_re_frmt(mvstr: str) -> str:
        mv_str_lst = mvstr.split(".")
        mv_str_lst.insert(1, r"\.")
        return "".join(mv_str_lst)

    reg_mv_base = r"[\s]*\* - "  # In support table, major versions are entered as "\t * - \d.x"
    reg_date = re.compile(r"[\d]{4}-[\d]{2}-[\d]{2}")
    mv_regs = {mv: re.compile(reg_mv_base + _major_version_re_frmt(mv)) for mv in DEPRECATION_DATE_MAP}

    def _match_mv_reg(a_line: str, reg_exp, mvstr: str) -> Optional[str]:  # pylint: disable=inconsistent-return-statements
        """Match a Major Version string in a row of the support version table
        :return None or Major Version String
        """
        if reg_exp.match(a_line):
            return mvstr

    def _match_mv_regs(a_line: str) -> Optional[str]:  # pylint: disable=inconsistent-return-statements
        """Check for any Major Version string in a row
        :return None or Major Version String
        """
        for mv in DEPRECATION_DATE_MAP:
            return_str = _match_mv_reg(a_line, mv_regs[mv], mv)
            if return_str:
                return return_str

    map_mvstr_date = {}
    support_policy = read("../../SUPPORT_POLICY.rst").splitlines()
    for line_number, line in enumerate(support_policy):
        a_mv = _match_mv_regs(line)
        if a_mv:
            map_mvstr_date[a_mv] = reg_date.search(support_policy[line_number + mv_date_line_offset]).group()
    return map_mvstr_date


@pytest.fixture(scope="module")
def parsed_deprecation_date_map():
    try:
        return _parse_support_policy()
    except Exception:
        raise RuntimeError(
            "The Format of SUPPORT_POLICY.rst has changed! " "The logic in test_compatability must be updated!"
        )


def test_deprecation_date_map_accurate(parsed_deprecation_date_map):
    assert (
        parsed_deprecation_date_map == DEPRECATION_DATE_MAP
    ), "The DEPRECATION_DATE_MAP in aws_encryption_sdk.compatability is not accurate!"


class TestWarnDeprecatedPython:
    def test_happy_version(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = 3
            v_info.minor = 6
            with pytest.warns(None) as record:
                _warn_deprecated_python()
            assert len(record) == 0

    def test_below_warn(self):
        with mock.patch.object(sys, "version_info") as v_info:
            v_info.major = 2
            v_info.minor = 7
            with pytest.warns(DeprecationWarning):
                _warn_deprecated_python()
