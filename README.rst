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

* Python 3.7+
* cryptography >= 3.4.6
* boto3 >= 1.10.0
* attrs

Recommended Prerequisites
=========================

* aws-cryptographic-material-providers: >= 1.0.0 (TODO-MPL: versionme)
  * Requires Python 3.11+.

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install additional prerequisites as
   detailed in the `cryptography installation guide`_ for your operating system.

   .. code::

       $ pip install "aws-encryption-sdk[MPL]"

The `[MPL]` suffix also installs the `AWS Cryptographic Material Providers Library (MPL)`_.
This is a library that contains interfaces for encrypting and decrypting your data.
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
CMMs that use master key providers have been deprecated since v4 of this library.

Legacy Concepts
===============
These concepts mention components that have been deprecated since v4 of this library.
These components have been superseded by new components in the `AWS Cryptographic Material Providers Library (MPL)`_.
Please avoid using these and instead use components in the MPL.

Master Key Providers
--------------------
Master key providers are resources that provide master keys.
An example of a master key provider is `AWS KMS`_.

To encrypt data in this client, a ``MasterKeyProvider`` object must contain at least one ``MasterKey`` object.

``MasterKeyProvider`` objects can also contain other ``MasterKeyProvider`` objects.

NOTE: Master key providers are deprecated
and have been superseded by keyrings
provided by the `AWS Cryptographic Material Providers Library (MPL)`_.
Please install this library and migrate master key providers to keyring interfaces.

Master Keys
-----------
Master keys generate, encrypt, and decrypt data keys.
An example of a master key is a `KMS customer master key (CMK)`_.

NOTE: Master keys are deprecated
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
(You may also provide an instance of a legacy master key provider, but this is not recommended.)
The examples in this README use the ``AwsKmsKeyring`` class.
Note: You must also install the `AWS Cryptographic Material Providers Library (MPL)`_ to use this class.


AwsKmsKeyring
=============================
A ``AwsKmsKeyring`` is configured with an AWS KMS key ARN whose AWS KMS key
will be used to generate, encrypt, and decrypt data keys.
On encryption, it encrypts the plaintext with the data key.
On decryption, it decrypts an encrypted version of the data key,
then uses the decrypted data key to decrypt the ciphertext.

To create a ``AwsKmsKeyring`` you must provide a AWS KMS key ARN.
For keyrings that will only be used for encryption,
you can use any valid `KMS key identifier`_.
For providers that will be used for decryption,
you must use the key ARN.
Key ids, alias names, and alias ARNs are not supported for decryption.

Because the ``AwsKmsKeyring`` uses the `boto3 SDK`_ to interact with `AWS KMS`_,
it requires AWS Credentials.
To provide these credentials, use the `standard means by which boto3 locates credentials`_ or provide a
pre-existing instance of a ``botocore session`` to the ``AwsKmsKeyring``.
This latter option can be useful if you have an alternate way to store your AWS credentials or
you want to reuse an existing instance of a botocore session in order to decrease startup costs.

TODO-MPL: Code example

If you want to configure a keyring with multiple AWS KMS keys, see the multi-keyring.

MultiKeyring
============

A ``MultiKeyring`` is configured with an optional generator keyring and a list of child keyrings.

TODO-MPL: More words

TODO-MPL: Code example

AwsKmsDiscoveryKeyring
======================
We recommend using an ``AwsKmsKeyring`` in order to ensure that you can only
encrypt and decrypt data using the AWS KMS key ARN you expect,
or a ``MultiKeyring`` if you are using multiple keys. However, if you are unable to
explicitly identify the AWS KMS key ARNs that should be used for decryption, you can instead
use a ``AwsKmsDiscoveryKeyring`` for decryption operations. This provider
attempts decryption of any ciphertexts as long as they match a ``DiscoveryFilter`` that
you configure. A ``DiscoveryFilter`` consists of a list of AWS account ids and an AWS
partition.

TODO-MPL: Code example

If you do not want to filter the set of allowed accounts, you can also omit the ``discovery_filter`` argument.

Note that a ``AwsKmsDiscoveryKeyring`` cannot be used for encryption operations.

Encryption and Decryption
=========================
After you create an instance of an ``EncryptionSDKClient`` and a ``Keyring``, you can use either of
the client's two ``encrypt``/``decrypt`` functions to encrypt and decrypt your data.

TODO-MPL: Code example; basic example with keyring

You can provide an `encryption context`_: a form of additional authenticating information.

TODO-MPL: Code example with encryption context

Streaming
=========
If you are handling large files or simply do not want to put the entire plaintext or ciphertext in
memory at once, you can use this library's streaming clients directly. The streaming clients are
file-like objects, and behave exactly as you would expect a Python file object to behave,
offering context manager and iteration support.

TODO-MPL: Update code example to use a keyring

.. code:: python

    import aws_encryption_sdk
    from aws_encryption_sdk.identifiers import CommitmentPolicy
    import filecmp

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    # TODO-MPL: create a keyring
    plaintext_filename = 'my-secret-data.dat'
    ciphertext_filename = 'my-encrypted-data.ct'

    with open(plaintext_filename, 'rb') as pt_file, open(ciphertext_filename, 'wb') as ct_file:
        with client.stream(
            mode='e',
            source=pt_file,
            keyring = # TODO-MPL: provide keyring
        ) as encryptor:
            for chunk in encryptor:
                ct_file.write(chunk)

    decrypted_filename = 'my-decrypted-data.dat'

    with open(ciphertext_filename, 'rb') as ct_file, open(decrypted_filename, 'wb') as pt_file:
        with client.stream(
            mode='d',
            source=ct_file,
            keyring = # TODO-MPL: provide keyring
        ) as decryptor:
            for chunk in decryptor:
                pt_file.write(chunk)

    assert filecmp.cmp(plaintext_filename, decrypted_filename)
    assert encryptor.header.encryption_context == decryptor.header.encryption_context

Performance Considerations
==========================
Adjusting the frame size can significantly improve the performance of encrypt/decrypt operations with this library.

Processing each frame in a framed message involves a certain amount of overhead.  If you are encrypting a large file,
increasing the frame size can offer potentially significant performance gains.  We recommend that you tune these values
to your use-case in order to obtain peak performance.

Thread safety
==========================
TODO-MPL: need to write about keyring thread safety.
kms keyrings definitely not thread safe.
raw keyrings need testing, but may be launched as not thread safe.

The ``EncryptionSDKClient`` class is thread safe.
But instances of key material providers (i.e. keyrings or legacy master key providers) that call AWS KMS
(ex. ``AwsKmsKeyring`` or other KMS keyrings; ``BaseKmsMasterKeyProvider`` or children of this class)
MUST not be shared between threads
for the reasons outlined in `the boto3 docs <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html#multithreading-or-multiprocessing-with-resources>`_.

Because these key material providers create a `new boto3 sessions <https://github.com/aws/aws-encryption-sdk-python/blob/08f305a9b7b5fc897d9cafac55fb98f3f2a6fe13/src/aws_encryption_sdk/key_providers/kms.py#L665-L674>`_ per region,
users do not need to create a client for every region in every thread;
a single key material provider per thread is sufficient.

(The ``BaseKMSMasterKeyProvider`` is the internal parent class of all the legacy KMS master key providers.)

Finally, while the ``CryptoMaterialsCache`` is thread safe,
sharing entries in that cache across threads needs to be done carefully
(see the !Note about partition name `in the API Docs <https://aws-encryption-sdk-python.readthedocs.io/en/latest/generated/aws_encryption_sdk.materials_managers.caching.html#aws_encryption_sdk.materials_managers.caching.CachingCryptoMaterialsManager>`_).

.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _Read the Docs: http://aws-encryption-sdk-python.readthedocs.io/en/latest/
.. _GitHub: https://github.com/aws/aws-encryption-sdk-python/
.. _AWS KMS: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
.. _KMS customer master key (CMK): https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys
.. _KMS key identifier: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
.. _boto3 SDK: https://boto3.readthedocs.io/en/latest/
.. _standard means by which boto3 locates credentials: https://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _final message: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
.. _encryption context: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
.. _Security issue notifications: ./CONTRIBUTING.md#security-issue-notifications
.. _Support Policy: ./SUPPORT_POLICY.rst
.. _AWS Cryptographic Material Providers Library (MPL): https://github.com/aws/aws-cryptographic-material-providers-library
.. _AWS Documentation for Keyrings: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html
