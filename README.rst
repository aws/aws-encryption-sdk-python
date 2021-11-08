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

* Python 3.6+
* cryptography >= 2.5.0
* boto3 >= 1.10.0
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
There are four main concepts that you need to understand to use this library:

Cryptographic Materials Managers
--------------------------------
Cryptographic materials managers (CMMs) are resources that collect cryptographic materials and prepare them for
use by the Encryption SDK core logic.

An example of a CMM is the default CMM, which is automatically generated anywhere a caller provides a master
key provider. The default CMM collects encrypted data keys from all master keys referenced by the master key
provider.

An example of a more advanced CMM is the caching CMM, which caches cryptographic materials provided by another CMM.

Master Key Providers
--------------------
Master key providers are resources that provide master keys.
An example of a master key provider is `AWS KMS`_.

To encrypt data in this client, a ``MasterKeyProvider`` object must contain at least one ``MasterKey`` object.

``MasterKeyProvider`` objects can also contain other ``MasterKeyProvider`` objects.

Master Keys
-----------
Master keys generate, encrypt, and decrypt data keys.
An example of a master key is a `KMS customer master key (CMK)`_.

Data Keys
---------
Data keys are the encryption keys that are used to encrypt your data. If your algorithm suite
uses a key derivation function, the data key is used to generate the key that directly encrypts the data.

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


You must then create an instance of either a master key provider or a CMM. The examples in this
readme use the ``StrictAwsKmsMasterKeyProvider`` class.


StrictAwsKmsMasterKeyProvider
=============================
A ``StrictAwsKmsMasterKeyProvider`` is configured with an explicit list of AWS KMS
CMKs with which to encrypt and decrypt data. On encryption, it encrypts the plaintext with all
configured CMKs. On decryption, it only attempts to decrypt ciphertexts that have been wrapped
with a CMK that matches one of the configured CMK ARNs.

To create a ``StrictAwsKmsMasterKeyProvider`` you must provide one or more CMKs. For providers that will only
be used for encryption, you can use any valid `KMS key identifier`_. For providers that will be used for decryption, you
must use the key ARN; key ids, alias names, and alias ARNs are not supported.

Because the ``StrictAwsKmsMasterKeyProvider`` uses the `boto3 SDK`_ to interact with `AWS KMS`_,
it requires AWS Credentials.
To provide these credentials, use the `standard means by which boto3 locates credentials`_ or provide a
pre-existing instance of a ``botocore session`` to the ``StrictAwsKmsMasterKeyProvider``.
This latter option can be useful if you have an alternate way to store your AWS credentials or
you want to reuse an existing instance of a botocore session in order to decrease startup costs.

If you configure the the ``StrictAwsKmsMasterKeyProvider`` with multiple CMKs, the `final message`_
will include a copy of the data key encrypted by each configured CMK.

.. code:: python

    import aws_encryption_sdk

    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ])

You can add CMKs from multiple regions to the ``StrictAwsKmsMasterKeyProvider``.

.. code:: python

    import aws_encryption_sdk

    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        'arn:aws:kms:us-west-2:3333333333333:key/33333333-3333-3333-3333-333333333333',
        'arn:aws:kms:ap-northeast-1:4444444444444:key/44444444-4444-4444-4444-444444444444'
    ])


DiscoveryAwsKmsMasterKeyProvider
================================
We recommend using a ``StrictAwsKmsMasterKeyProvider`` in order to ensure that you can only
encrypt and decrypt data using the AWS KMS CMKs you expect. However, if you are unable to
explicitly identify the AWS KMS CMKs that should be used for decryption, you can instead
use a ``DiscoveryAwsKmsMasterKeyProvider`` for decryption operations. This provider
attempts decryption of any ciphertexts as long as they match a ``DiscoveryFilter`` that
you configure. A ``DiscoveryFilter`` consists of a list of AWS account ids and an AWS
partition.

.. code:: python

    import aws_encryption_sdk
    from aws_encryption_sdk.key_providers.kms import DiscoveryFilter

    discovery_filter = DiscoveryFilter(
        account_ids=['222222222222', '333333333333'],
        partition='aws'
    )
    kms_key_provider = aws_encryption_sdk.DiscoveryAwsKmsMasterKeyProvider(
        discovery_filter=discovery_filter
    )

If you do not want to filter the set of allowed accounts, you can also omit the ``discovery_filter`` argument.

Note that a ``DiscoveryAwsKmsMasterKeyProvider`` cannot be used for encryption operations.

Encryption and Decryption
=========================
After you create an instance of an ``EncryptionSDKClient`` and a ``MasterKeyProvider``, you can use either of
the client's two ``encrypt``/``decrypt`` functions to encrypt and decrypt your data.

.. code:: python

    import aws_encryption_sdk
    from aws_encryption_sdk.identifiers import CommitmentPolicy

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ])
    my_plaintext = b'This is some super secret data!  Yup, sure is!'

    my_ciphertext, encryptor_header = client.encrypt(
        source=my_plaintext,
        key_provider=kms_key_provider
    )

    decrypted_plaintext, decryptor_header = client.decrypt(
        source=my_ciphertext,
        key_provider=kms_key_provider
    )

    assert my_plaintext == decrypted_plaintext
    assert encryptor_header.encryption_context == decryptor_header.encryption_context

You can provide an `encryption context`_: a form of additional authenticating information.

.. code:: python

    import aws_encryption_sdk
    from aws_encryption_sdk.identifiers import CommitmentPolicy

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ])
    my_plaintext = b'This is some super secret data!  Yup, sure is!'

    my_ciphertext, encryptor_header = client.encrypt(
        source=my_plaintext,
        key_provider=kms_key_provider,
        encryption_context={
            'not really': 'a secret',
            'but adds': 'some authentication'
        }
    )

    decrypted_plaintext, decryptor_header = client.decrypt(
        source=my_ciphertext,
        key_provider=kms_key_provider
    )

    assert my_plaintext == decrypted_plaintext
    assert encryptor_header.encryption_context == decryptor_header.encryption_context


Streaming
=========
If you are handling large files or simply do not want to put the entire plaintext or ciphertext in
memory at once, you can use this library's streaming clients directly. The streaming clients are
file-like objects, and behave exactly as you would expect a Python file object to behave,
offering context manager and iteration support.

.. code:: python

    import aws_encryption_sdk
    from aws_encryption_sdk.identifiers import CommitmentPolicy
    import filecmp

    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    )

    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
        'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ])
    plaintext_filename = 'my-secret-data.dat'
    ciphertext_filename = 'my-encrypted-data.ct'

    with open(plaintext_filename, 'rb') as pt_file, open(ciphertext_filename, 'wb') as ct_file:
        with client.stream(
            mode='e',
            source=pt_file,
            key_provider=kms_key_provider
        ) as encryptor:
            for chunk in encryptor:
                ct_file.write(chunk)

    new_plaintext_filename = 'my-decrypted-data.dat'

    with open(ciphertext_filename, 'rb') as ct_file, open(new_plaintext_filename, 'wb') as pt_file:
        with client.stream(
            mode='d',
            source=ct_file,
            key_provider=kms_key_provider
        ) as decryptor:
            for chunk in decryptor:
                pt_file.write(chunk)

    assert filecmp.cmp(plaintext_filename, new_plaintext_filename)
    assert encryptor.header.encryption_context == decryptor.header.encryption_context

Performance Considerations
==========================
Adjusting the frame size can significantly improve the performance of encrypt/decrypt operations with this library.

Processing each frame in a framed message involves a certain amount of overhead.  If you are encrypting a large file,
increasing the frame size can offer potentially significant performance gains.  We recommend that you tune these values
to your use-case in order to obtain peak performance.


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
