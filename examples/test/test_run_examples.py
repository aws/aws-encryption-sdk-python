# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test all examples."""
from importlib import import_module

import pytest

from .examples_test_utils import all_examples, build_kwargs

pytestmark = [pytest.mark.examples]


@pytest.mark.parametrize("import_path", all_examples())
def test_examples(import_path, tmp_path):
    module = import_module(name=import_path, package=__package__)
    try:
        run_function = module.run
    except AttributeError:
        pytest.skip("Module lacks 'run' function.")
        return

    kwargs = build_kwargs(function=run_function, temp_dir=tmp_path)

    run_function(**kwargs)
