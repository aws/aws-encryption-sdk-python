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


from integration_test_utils import get_cmk_arn  # noqa pylint: disable=unused-import,import-error
