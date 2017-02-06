"""Helper functions for consistently obtaining str and bytes objects in both Python2 and Python3."""
import codecs

import six

import aws_encryption_sdk.internal.defaults


def to_str(data):
    """Takes an input str or bytes object and returns an equivalent str object.

    :param data: Input data
    :type data: str or bytes
    :returns: Data normalized to str
    :rtype: str
    """
    if isinstance(data, bytes):
        return codecs.decode(data, aws_encryption_sdk.internal.defaults.ENCODING)
    return data


def to_bytes(data):
    """Takes an input str or bytes object and returns an equivalent bytes object.

    :param data: Input data
    :type data: str or bytes
    :returns: Data normalized to bytes
    :rtype: bytes
    """
    if isinstance(data, six.string_types) and not isinstance(data, bytes):
        return codecs.encode(data, aws_encryption_sdk.internal.defaults.ENCODING)
    return data
