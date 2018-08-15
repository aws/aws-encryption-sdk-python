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
"""Helper stream utility objects for AWS Encryption SDK."""
from wrapt import ObjectProxy

from aws_encryption_sdk.exceptions import ActionNotAllowedError


class ROStream(ObjectProxy):
    """Provides a read-only interface on top of a file-like object.

    Used to provide MasterKeyProviders with read-only access to plaintext.

    :param wrapped: File-like object
    """

    def write(self, b):  # pylint: disable=unused-argument
        """Blocks calls to write.

        :raises ActionNotAllowedError: when called
        """
        raise ActionNotAllowedError("Write not allowed on ROStream objects")


class TeeStream(ObjectProxy):
    """Provides a ``tee``-like interface on top of a file-like object, which collects read bytes
    into a local :class:`io.BytesIO`.

    :param wrapped: File-like object
    :param tee: Stream to copy read bytes into.
    :type tee: io.BaseIO
    """

    __tee = None  # Prime ObjectProxy's attributes to allow setting in init.

    def __init__(self, wrapped, tee):
        """Creates the local tee stream."""
        super(TeeStream, self).__init__(wrapped)
        self.__tee = tee

    def read(self, b=None):
        """Reads data from source, copying it into ``tee`` before returning.

        :param int b: number of bytes to read
        """
        data = self.__wrapped__.read(b)
        self.__tee.write(data)
        return data
