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
import io

from aws_encryption_sdk.exceptions import ActionNotAllowedError


class PassThroughStream(object):
    """Provides a pass-through interface on top of a file-like object.

    :param source_stream: File-like object
    """

    def __init__(self, source_stream):
        """Prepares the passthroughs."""
        self._source_stream = source_stream
        self._duplicate_api()

    def _duplicate_api(self):
        """Maps the source file-like API onto this object."""
        source_attributes = set([
            attribute for attribute in dir(self._source_stream)
            if not attribute.startswith('_')
        ])
        self_attributes = set(dir(self))
        for attribute in source_attributes.difference(self_attributes):
            setattr(self, attribute, getattr(self._source_stream, attribute))


class ROStream(PassThroughStream):
    """Provides a read-only interface on top of a file-like object.

    Used to provide MasterKeyProviders with read-only access to plaintext.

    :param source_stream: File-like object
    """

    def write(self, b):  # pylint: disable=unused-argument
        """Blocks calls to write.

        :raises ActionNotAllowedError: when called
        """
        raise ActionNotAllowedError('Write not allowed on ROStream objects')


class TeeStream(PassThroughStream):
    """Provides a ``tee``-like interface on top of a file-like object, which collects read bytes
    into a local :class:`io.BytesIO`.

    :param source_stream: File-like object
    """

    def __init__(self, source_stream):
        """Creates the local tee stream."""
        self.tee = io.BytesIO()
        super(TeeStream, self).__init__(source_stream)

    def read(self, b=None):
        """Reads data from source, copying it into ``tee`` before returning.

        :param int b: number of bytes to read
        """
        data = self._source_stream.read(b)
        self.tee.write(data)
        return data
