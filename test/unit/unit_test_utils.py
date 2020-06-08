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
"""Utility functions to handle common test framework functions."""
import copy
import io
import itertools

from aws_encryption_sdk.internal.utils.streams import InsistentReaderBytesIO


def all_valid_kwargs(valid_kwargs):
    valid = []
    for cls, kwargs_sets in valid_kwargs.items():
        for kwargs in kwargs_sets:
            valid.append((cls, kwargs))
    return valid


def all_invalid_kwargs(valid_kwargs, invalid_kwargs=None):
    if invalid_kwargs is None:
        invalid_kwargs = {}
    invalid = []
    for cls, kwargs_sets in valid_kwargs.items():
        if cls in invalid_kwargs:
            for _kwargs in invalid_kwargs[cls]:
                invalid.append((cls, _kwargs))
            continue

        kwargs = kwargs_sets[-1]
        for key in kwargs:
            _kwargs = copy.deepcopy(kwargs)
            _kwargs.update({key: None})
            invalid.append((cls, _kwargs))
    return invalid


def build_valid_kwargs_list(base, optional_kwargs):
    valid_kwargs = []
    options = optional_kwargs.items()
    for i in range(len(optional_kwargs)):
        for valid_options in itertools.combinations(options, i):
            _kwargs = base.copy()
            _kwargs.update(dict(valid_options))
            valid_kwargs.append(_kwargs)
    return valid_kwargs


class SometimesIncompleteReaderIO(io.BytesIO):
    def __init__(self, *args, **kwargs):
        self._read_counter = 0
        super(SometimesIncompleteReaderIO, self).__init__(*args, **kwargs)

    def read(self, size=-1):
        """Every other read request, return fewer than the requested number of bytes if more than one byte requested."""
        self._read_counter += 1
        if size > 1 and self._read_counter % 2 == 0:
            size //= 2
        return super(SometimesIncompleteReaderIO, self).read(size)


class NothingButRead(object):
    def __init__(self, data):
        self._data = io.BytesIO(data)

    def read(self, size=-1):
        return self._data.read(size)


class ExactlyTwoReads(SometimesIncompleteReaderIO):
    def read(self, size=-1):
        if self._read_counter >= 2:
            self.close()
        return super(ExactlyTwoReads, self).read(size)


class FailingTeller(object):
    def tell(self):
        raise IOError("Tell not allowed!")


def assert_prepped_stream_identity(prepped_stream, wrapped_type):
    # Check the wrapped stream
    assert isinstance(prepped_stream, wrapped_type)
    # Check the wrapping streams
    assert isinstance(prepped_stream, InsistentReaderBytesIO)
