# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Helper utilities for use while testing examples."""
import os
import sys

os.environ["AWS_ENCRYPTION_SDK_EXAMPLES_TESTING"] = "yes"
sys.path.extend([os.sep.join([os.path.dirname(__file__), "..", "..", "test", "integration"])])

static_plaintext = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent non feugiat leo. Aenean iaculis tellus ut velit consectetur, quis convallis orci eleifend. Sed eu dictum sapien. Nulla facilisi. Suspendisse potenti. Proin vehicula vehicula maximus. Donec varius et elit vel rutrum. Nulla lacinia neque turpis, quis consequat orci pharetra et. Etiam consequat ullamcorper mauris. Vivamus molestie mollis mauris a gravida. Curabitur sed bibendum nisl.'
static_plaintext = str.encode(static_plaintext)

from integration_test_utils import get_cmk_arn  # noqa pylint: disable=unused-import,import-error

