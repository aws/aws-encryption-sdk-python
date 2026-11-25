# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Docstring type references must name AlgorithmSuite, not its alias Algorithm.

Sphinx does not follow the ``Algorithm = AlgorithmSuite`` alias when it resolves
``:type:`` and ``:rtype:`` references, so documented parameters of that type render
without a link.
"""
import os
import re

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
ALIAS_TYPE_REFERENCE = re.compile(r"^\s*:(?:type|rtype)[^:]*:.*identifiers\.Algorithm\b(?!Suite)")


def test_docstrings_do_not_reference_algorithm_alias():
    offenders = []
    for root, _dirs, files in os.walk(SRC_DIR):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as source:
                for line_number, line in enumerate(source, start=1):
                    if ALIAS_TYPE_REFERENCE.match(line):
                        offenders.append("{}:{}".format(os.path.relpath(path, SRC_DIR), line_number))
    assert not offenders, "Use AlgorithmSuite in :type:/:rtype: references: " + ", ".join(offenders)
