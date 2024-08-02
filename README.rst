##################
aws-encryption-sdk
##################

.. image:: https://img.shields.io/pypi/v/aws-encryption-sdk.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk
   :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/aws-encryption-sdk.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk
   :alt: Supported Python Versions

.. image:: https://img.shields.io/badge/code_style-black-000000.svg
   :target: https://github.com/ambv/black
   :alt: Code style: black

.. image:: https://readthedocs.org/projects/aws-encryption-sdk-python/badge/
   :target: https://aws-encryption-sdk-python.readthedocs.io/en/stable/
   :alt: Documentation Status

The AWS Encryption SDK for Python provides a fully compliant, native Python implementation of the `AWS Encryption SDK`_.

The latest full documentation can be found at `Read the Docs`_.

Find us on `GitHub`_.

`Security issue notifications`_

See `Support Policy`_ for details on the current support status of all major versions of this library.

***************
Getting Started
***************
Required Prerequisites
======================

* Python 3.8+
* cryptography >= 3.4.6
* boto3 >= 1.10.0
* attrs

Recommended Prerequisites
=========================

* aws-cryptographic-material-providers: >= TODO.TODO.TODO (TODO-MPL: versionme)
    * Requires Python 3.11+.

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install additional prerequisites as
   detailed in the `cryptography installation guide`_ for your operating system.

   .. code::

       $ pip install "aws-encryption-sdk[MPL]"

The `[MPL]` suffix also installs the `AWS Cryptographic Material Providers Library (MPL)`_.
This is a library that contains constructs for encrypting and decrypting your data.
We highly recommend installing the MPL.
However, if you do not wish to install the MPL, omit the `[MPL]` suffix.

Concepts
========
There are three main concepts that you need to understand to use this library:

Data Keys
---------
Data keys are the encryption keys that are used to encrypt your data. If your algorithm suite
uses a key derivation function, the data key is used to generate the key that directly encrypts the data.

Keyrings
--------
Keyrings are resources that generate, encrypt, and decrypt data keys.
You specify a keyring when encrypting and the same or a different keyring when decrypting.

Note: You must also install the `AWS Cryptographic Material Providers Library (MPL)`_ to create and use keyrings.

For more information, see the `AWS Documentation for Keyrings`_.

Cryptographic Materials Managers
--------------------------------
Cryptographic materials managers (CMMs) are resources that collect cryptographic materials and prepare them for
use by the Encryption SDK core logic.

An example of a CMM is the default CMM,
which is automatically generated anywhere a caller provides a keyring.

Note: You must also install the `AWS Cryptographic Material Providers Library (MPL)`_
to create and use CMMs that use keyrings.
CMMs that use master key providers have been marked as legacy since v4 of this library.

Legacy Concepts
===============
This section describes legacy concepts introduced in earlier versions of this library.
These components have been superseded by new components in the `AWS Cryptographic Material Providers Library (MPL)`_.
Please avoid using these components, and instead use components in the MPL.

Master Key Providers
--------------------
Master key providers are resources that provide master keys.

To encrypt data in this client, a ``MasterKeyProvider`` object must contain at least one ``MasterKey`` object.

``MasterKeyProvider`` objects can also contain other ``MasterKeyProvider`` objects.

NOTE: Master key providers are legacy components
and have been superseded by keyrings
provided by the `AWS Cryptographic Material Providers Library (MPL)`_.
Please install this library and migrate master key providers to keyring interfaces.

Master Keys
-----------
Master keys generate, encrypt, and decrypt data keys.
An example of a master key is an `AWS KMS key`_.

NOTE: Master keys are legacy constructs
and have been superseded by keyrings
provided by the `AWS Cryptographic Material Providers Library (MPL)`_.
Please install this library and migrate master key providers to keyring interfaces.

*****
Usage
*****

EncryptionSDKClient
===================
To use this module, you (the caller) must first create an instance of the ``EncryptionSDKClient`` class.
The constructor to this class accepts an optional keyword argument, ``commitment_policy``, that controls
which algorithm suites can be used for encryption and decryption. If no value
is provided for this argument, a default value of ``REQUIRE_ENCRYPT_REQUIRE_DECRYPT`` is used. Unless
you have specialized performance requirements or are in the process of migrating from an older
version of the AWS Encryption SDK, we recommend using the default value.

.. code:: python

    import aws_encryption_sdk
    from aws_encryption_sdk.identifiers import CommitmentPolicy


    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )


You must then create an instance of either a keyring (with the MPL installed) or a CMM.
Note: You must also install the `AWS Cryptographic Material Providers Library (MPL)`_ to use keyrings.
(You may also provide an instance of a legacy master key provider, but this is not recommended.)


AwsKmsMultiKeyring
==================

An ``AwsKmsMultiKeyring`` is configured with a generator keyring and a list of
child keyrings of type ``AwsKmsKeyring``. The effect is like using several keyrings
in a series. When you use a multi-keyring to encrypt data, any of the wrapping keys
in any of its keyrings can decrypt that data.

On encryption, the generator keyring generates and encrypts the plaintext data key.
Then, all of the wrapping keys in all of the child keyrings encrypt the same plaintext data key.
The final `encrypted message`_ will include a copy of the data key encrypted by each configured key.
On decryption, the AWS Encryption SDK uses the keyrings to try to decrypt one of the encrypted data keys.
The keyrings are called in the order that they are specified in the multi-keyring.
Processing stops as soon as any key in any keyring can decrypt an encrypted data key.

An individual ``AwsKmsKeyring`` in an ``AwsKmsMultiKeyring`` is configured with an
AWS KMS key ARN.
For keyrings that will only be used for encryption,
you can use any valid `KMS key identifier`_.
For providers that will be used for decryption,
you must use the key ARN.
Key ids, alias names, and alias ARNs are not supported for decryption.

Because the ``AwsKmsMultiKeyring`` uses the `boto3 SDK`_ to interact with `AWS KMS`_,
it requires AWS Credentials.
To provide these credentials, use the `standard means by which boto3 locates credentials`_ or provide a
pre-existing instance of a ``botocore session`` to the ``AwsKmsMultiKeyring``.
This latter option can be useful if you have an alternate way to store your AWS credentials or
you want to reuse an existing instance of a botocore session in order to decrease startup costs.
You can also add KMS keys from multiple regions to the ``AwsKmsMultiKeyring``.

See `examples/src/aws_kms_multi_keyring_example.py`_ for a code example configuring and using
a ``AwsKmsMultiKeyring`` with the ``EncryptionSDKClient``.

AwsKmsDiscoveryKeyring
======================
We recommend using an ``AwsKmsMultiKeyring`` in order to ensure that you can only
encrypt and decrypt data using the AWS KMS key ARN you expect. However, if you are unable to
explicitly identify the AWS KMS key ARNs that should be used for decryption, you can instead
use an ``AwsKmsDiscoveryKeyring`` for decryption operations. This provider
attempts decryption of any ciphertexts as long as they match a ``DiscoveryFilter`` that
you configure. A ``DiscoveryFilter`` consists of a list of AWS account ids and an AWS
partition.
If you do not want to filter the set of allowed accounts, you can also omit the ``discovery_filter`` argument.

Note that an ``AwsKmsDiscoveryKeyring`` cannot be used for encryption operations.

See `examples/src/aws_kms_discovery_keyring_example.py`_ for a code example configuring and using
an ``AwsKmsDiscoveryKeyring`` with the ``EncryptionSDKClient``.


Encryption and Decryption
=========================
After you create an instance of an ``EncryptionSDKClient`` and a ``Keyring``, you can use
the client's ``encrypt`` and ``decrypt`` functions to encrypt and decrypt your data.

You can also provide an `encryption context`_: a form of additional authenticating information.

See code in the `examples/src/`_ directory for code examples configuring and using
keyrings and encryption context with the ``EncryptionSDKClient``.

Streaming
=========
If you are handling large files or simply do not want to put the entire plaintext or ciphertext in
memory at once, you can use this library's streaming clients directly. The streaming clients are
file-like objects, and behave exactly as you would expect a Python file object to behave,
offering context manager and iteration support.

See `examples/src/file_streaming_example.py`_ for a code example streaming data to and from files.

Performance Considerations
==========================
Adjusting the frame size can significantly improve the performance of encrypt/decrypt operations with this library.

Processing each frame in a framed message involves a certain amount of overhead. If you are encrypting a large file,
increasing the frame size can offer potentially significant performance gains. We recommend that you tune these values
to your use-case in order to obtain peak performance.

Thread safety
==========================
The ``EncryptionSDKClient`` and all provided ``CryptoMaterialsManager`` in this library are thread safe.
But instances of ``BaseKMSMasterKeyProvider`` MUST not be shared between threads,
for the reasons outlined in `the boto3 docs <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html#multithreading-or-multiprocessing-with-resources>`_.

Because the ``BaseKMSMaterKeyProvider`` creates a `new boto3 sessions <https://github.com/aws/aws-encryption-sdk-python/blob/08f305a9b7b5fc897d9cafac55fb98f3f2a6fe13/src/aws_encryption_sdk/key_providers/kms.py#L665-L674>`_ per region,
users do not need to create a client for every region in every thread;
a new  ``BaseKMSMasterKeyProvider`` per thread is sufficient.

(The ``BaseKMSMasterKeyProvider`` is the internal parent class of all the KMS Providers.)

Finally, while the ``CryptoMaterialsCache`` is thread safe,
sharing entries in that cache across threads needs to be done carefully
(see the !Note about partition name `in the API Docs <https://aws-encryption-sdk-python.readthedocs.io/en/latest/generated/aws_encryption_sdk.materials_managers.caching.html#aws_encryption_sdk.materials_managers.caching.CachingCryptoMaterialsManager>`_).

**Important:** Components from the `AWS Cryptographic Material Providers Library (MPL)`_
have separate thread safety considerations.
For more information, see the note on thread safety in that project's README (TODO-MPL: link)


.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _Read the Docs: http://aws-encryption-sdk-python.readthedocs.io/en/latest/
.. _GitHub: https://github.com/aws/aws-encryption-sdk-python/
.. _AWS KMS: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
.. _AWS KMS key: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys
.. _KMS key identifier: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
.. _boto3 SDK: https://boto3.readthedocs.io/en/latest/
.. _standard means by which boto3 locates credentials: https://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _encrypted message: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
.. _encryption context: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
.. _Security issue notifications: ./CONTRIBUTING.md#security-issue-notifications
.. _Support Policy: ./SUPPORT_POLICY.rst
.. _AWS Cryptographic Material Providers Library (MPL): https://github.com/aws/aws-cryptographic-material-providers-library
.. _AWS Documentation for Keyrings: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html
.. _examples/src/aws_kms_multi_keyring_example.py: https://github.com/aws/aws-encryption-sdk-python/blob/master/examples/src/aws_kms_multi_keyring_example.py
.. _examples/src/aws_kms_discovery_keyring_example.py: https://github.com/aws/aws-encryption-sdk-python/blob/master/examples/src/aws_kms_discovery_keyring_example.py
.. _examples/src/: https://github.com/aws/aws-encryption-sdk-python/tree/master/examples/src/
.. _examples/src/file_streaming_example.py: https://github.com/aws/aws-encryption-sdk-python/blob/master/examples/src/file_streaming_example.py
