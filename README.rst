##################
aws-encryption-sdk
##################

.. image:: https://img.shields.io/pypi/v/aws-encryption-sdk.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk
   :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/aws-encryption-sdk-cli.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk
   :alt: Supported Python Versions

.. image:: https://img.shields.io/badge/code_style-black-000000.svg
   :target: https://github.com/ambv/black
   :alt: Code style: black

.. image:: https://readthedocs.org/projects/aws-encryption-sdk-python/badge/
   :target: https://aws-encryption-sdk-python.readthedocs.io/en/stable/
   :alt: Documentation Status

.. image:: https://travis-ci.org/aws/aws-encryption-sdk-python.svg?branch=master
   :target: https://travis-ci.org/aws/aws-encryption-sdk-python

.. image:: https://ci.appveyor.com/api/projects/status/p3e2e63gsnp3cwd8/branch/master?svg=true
   :target: https://ci.appveyor.com/project/mattsb42-aws/aws-encryption-sdk-python-qvyet/branch/master

The AWS Encryption SDK for Python provides a fully compliant, native Python implementation of the `AWS Encryption SDK`_.

The latest full documentation can be found at `Read the Docs`_.

Find us on `GitHub`_.

***************
Getting Started
***************
Required Prerequisites
======================

* Python 2.7 or 3.5+
* cryptography >= 1.8.1
* boto3
* attrs

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install additional prerequisites as
   detailed in the `cryptography installation guide`_ for your operating system.

   .. code::

       $ pip install aws-encryption-sdk

Concepts
========
There are three main concepts that are helpful to understand when using the AWS Encryption SDK.

For further information, see the `AWS Encryption SDK developer guide concepts`_.

Cryptographic Materials Managers
--------------------------------
The cryptographic materials manager (CMM) assembles the cryptographic materials
that are used to encrypt and decrypt data.

`For more details,
see the AWS Encryption SDK developer guide cryptographic materials manager concept.
<https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#crypt-materials-manager>`_

Keyrings
--------

A keyring generates, encrypts, and decrypts data keys.

`For more details,
see the AWS Encryption SDK developer guide keyring concept.
<https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#keyring>`_

Data Keys
---------

A data key is an encryption key that the AWS Encryption SDK uses to encrypt your data.

`For more details,
see the AWS Encryption SDK developer guide data key concept.
<https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#DEK>`_

*****
Usage
*****

For examples of how to use these concepts to accomplish different tasks, see our `examples`_.

Performance Considerations
==========================
Adjusting the frame size can significantly improve the performance of encrypt/decrypt operations with this library.

Processing each frame in a framed message involves a certain amount of overhead.  If you are encrypting a large file,
increasing the frame size can offer potentially significant performance gains.  We recommend that you tune these values
to your use-case in order to obtain peak performance.


.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _AWS Encryption SDK developer guide concepts:
    https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _Read the Docs: http://aws-encryption-sdk-python.readthedocs.io/en/latest/
.. _GitHub: https://github.com/aws/aws-encryption-sdk-python/
.. _AWS KMS: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
.. _KMS customer master key (CMK): https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys
.. _boto3 SDK: https://boto3.readthedocs.io/en/latest/
.. _standard means by which boto3 locates credentials: https://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _final message: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
.. _encryption context: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
.. _examples: https://github.com/aws/aws-encryption-sdk-python/tree/master/examples
