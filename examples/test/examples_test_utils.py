# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper utilities for use while testing examples."""
import os
import sys
import inspect

import pytest
import six

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, Dict, Iterable, List  # noqa pylint: disable=unused-import

    # we only need pathlib here for typehints
    from pathlib import Path
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

HERE = os.path.abspath(os.path.dirname(__file__))
EXAMPLES_SOURCE = os.path.join(HERE, "..", "src")
SINGLE_CMK_ARG = "aws_kms_cmk_arn"
GENERATOR_CMK_ARG = "aws_kms_generator_cmk"
CHILD_CMK_ARG = "aws_kms_child_cmks"
PLAINTEXT_ARG = "source_plaintext"
PLAINTEXT_FILE_ARG = "source_plaintext_filename"

os.environ["AWS_ENCRYPTION_SDK_EXAMPLES_TESTING"] = "yes"
sys.path.extend([os.sep.join([os.path.dirname(__file__), "..", "..", "test", "integration"])])

static_plaintext = (
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    b"Praesent non feugiat leo. Aenean iaculis tellus ut velit consectetur, "
    b"quis convallis orci eleifend. Sed eu dictum sapien. Nulla facilisi. Suspendisse potenti. "
    b"Proin vehicula vehicula maximus. Donec varius et elit vel rutrum. Nulla lacinia neque turpis,"
    b" quis consequat orci pharetra et. Etiam consequat ullamcorper mauris. Vivamus molestie mollis "
    b"mauris a gravida. Curabitur sed bibendum nisl. Cras varius tortor non erat sodales, quis congue"
    b" tellus laoreet. Etiam fermentum purus eu diam sagittis, vitae commodo est vehicula. "
    b"Nulla feugiat viverra orci vel interdum. Quisque pulvinar elit eget nulla facilisis varius. "
    b"Mauris at suscipit sem. Aliquam in purus ut velit fringilla volutpat id non mi. "
    b"Curabitur quis nunc eleifend, ornare lectus non, fringilla quam. Nam maximus volutpat placerat. "
    b"Nulla ullamcorper lorem velit, nec sagittis ex tristique posuere. Aliquam fringilla magna commodo"
    b" libero faucibus tempor. Vestibulum non ligula tincidunt, finibus sapien in, sollicitudin "
    b"ex. Pellentesque congue laoreet mi in condimentum. Cras convallis nisi ac nunc tincidunt "
    b"venenatis. Suspendisse urna elit, cursus eu lacus a, aliquet porttitor mi. "
    b"Nulla vel congue nibh, sed condimentum dui. Ut ante ligula, blandit eu finibus nec, "
    b"scelerisque quis eros. Maecenas gravida odio eget nibh dictum, dictum varius lacus interdum. "
    b"Integer quis nulla vulputate, rhoncus diam vitae, mollis mauris. Sed ut porttitor dolor. "
    b"Fusce ut justo a ex bibendum imperdiet nec sit amet magna. Sed ullamcorper luctus augue, "
    b"tempor viverra elit interdum sed. Cras sit amet arcu eu turpis molestie sollicitudin. "
    b"Curabitur fermentum varius nibh, ut aliquet nisi. Aliquam id tempus tellus. "
    b"Nulla porttitor nulla at nibh interdum, quis sollicitudin erat egestas. "
    b"Ut blandit mauris quis efficitur efficitur. Morbi neque sapien, posuere ut aliquam eget, "
    b"aliquam at velit. Morbi sit amet rhoncus felis, et hendrerit sem. Nulla porta dictum ligula "
    b"eget iaculis. Cras lacinia ligula quis risus ultrices, sed consectetur metus imperdiet. "
    b"Nullam id enim vestibulum nibh ultricies auctor. Morbi neque lacus, faucibus vitae commodo quis, "
    b"malesuada sed velit."
)


from integration_test_utils import get_all_cmk_arns  # noqa pylint: disable=unused-import,import-error


def all_examples():
    # type: () -> Iterable[pytest.param]
    for (dirpath, _dirnames, filenames) in os.walk(EXAMPLES_SOURCE):
        for testfile in filenames:
            split_path = testfile.rsplit(".", 1)
            if len(split_path) != 2:
                continue
            stem, suffix = split_path
            if suffix == "py" and stem != "__init__":
                module_parent = dirpath[len(EXAMPLES_SOURCE) + 1 :].replace("/", ".")
                module_name = stem
                if module_parent:
                    import_path = "..src.{base}.{name}".format(base=module_parent, name=module_name)
                else:
                    import_path = "..src.{name}".format(name=module_name)

                yield pytest.param(import_path, id="{base}.{name}".format(base=module_parent, name=module_name))


def get_arg_names(function):
    # type: (Callable) -> List[str]
    if six.PY2:
        # getargspec was deprecated in CPython 3.0 but 2.7 does not have either of the new options
        spec = inspect.getargspec(function)  # pylint: disable=deprecated-method
        return spec.args

    spec = inspect.getfullargspec(function)
    return spec.args


def build_kwargs(function, temp_dir):
    # type: (Callable, Path) -> Dict[str, str]

    plaintext_file = temp_dir / "plaintext"
    plaintext_file.write_bytes(static_plaintext)

    cmk_arns = get_all_cmk_arns()

    args = get_arg_names(function)
    possible_kwargs = {
        SINGLE_CMK_ARG: cmk_arns[0],
        GENERATOR_CMK_ARG: cmk_arns[0],
        CHILD_CMK_ARG: cmk_arns[1:],
        PLAINTEXT_ARG: static_plaintext,
        PLAINTEXT_FILE_ARG: str(plaintext_file.absolute()),
    }
    kwargs = {}
    for name in args:
        try:
            kwargs[name] = possible_kwargs[name]
        except KeyError:
            pass
    return kwargs
