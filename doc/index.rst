aws-encryption-sdk
==================

`aws-encryption-sdk` is a fully compliant, native Python implementation of the `AWS Encryption SDK`_.

Installation
____________


You can install `aws-encryption-sdk` with `pip`::

    $ pip install aws-encryption-sdk


Usage
_____

Usage examples can be found in the `Python Examples`_ in the AWS documentation, or in the
:py:mod:`aws_encryption_sdk` module in this documentation.


Modules
_______

.. autosummary::
    :toctree: generated

    aws_encryption_sdk
    aws_encryption_sdk.exceptions
    aws_encryption_sdk.streaming_client
    aws_encryption_sdk.internal.crypto
    aws_encryption_sdk.internal.crypto.providers.base
    aws_encryption_sdk.internal.crypto.providers.kms
    aws_encryption_sdk.internal.crypto.providers.raw
    aws_encryption_sdk.internal.defaults
    aws_encryption_sdk.internal.formatting.deserialize
    aws_encryption_sdk.internal.formatting.encryption_context
    aws_encryption_sdk.internal.formatting.serialize
    aws_encryption_sdk.internal.identifiers
    aws_encryption_sdk.internal.str_ops
    aws_encryption_sdk.internal.structures
    aws_encryption_sdk.internal.utils

.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _Python Examples: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/example-code-python.html