# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test all examples."""
from importlib import import_module

import pytest

from .examples_test_utils import all_examples, aws_kms_cmk_arns, get_arg_names, static_plaintext

pytestmark = [pytest.mark.examples]
SINGLE_CMK_ARG = "aws_kms_cmk_arn"
GENERATOR_CMK_ARG = "aws_kms_generator_cmk"
CHILD_CMK_ARG = "aws_kms_child_cmks"
PLAINTEXT_ARG = "source_plaintext"
PLAINTEXT_FILE_ARG = "source_plaintext_filename"


@pytest.mark.parametrize("import_path", all_examples())
def test_examples(import_path, aws_kms_cmk_arns, tmp_path):
    module = import_module(name=import_path, package=__package__)
    try:
        run_function = getattr(module, "run")
    except AttributeError:
        pytest.skip("Module lacks 'run' function.")
        return

    plaintext_file = tmp_path / "plaintext"
    plaintext_file.write_bytes(static_plaintext)

    args = get_arg_names(run_function)
    possible_kwargs = {
        SINGLE_CMK_ARG: aws_kms_cmk_arns[0],
        GENERATOR_CMK_ARG: aws_kms_cmk_arns[0],
        CHILD_CMK_ARG: aws_kms_cmk_arns[1:],
        PLAINTEXT_ARG: static_plaintext,
        PLAINTEXT_FILE_ARG: str(plaintext_file.absolute()),
    }
    kwargs = {}
    for name in args:
        try:
            kwargs[name] = possible_kwargs[name]
        except KeyError:
            pass

    run_function(**kwargs)
