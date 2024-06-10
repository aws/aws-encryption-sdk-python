##################
Migration Examples
##################

The `Encryption SDK for Python`_ now uses the `AWS Cryptographic Material Providers Library`_. The MPL abstracts lower
level cryptographic materials management of encryption and decryption materials.

This directory contains migration examples for:

* Moving to Keyrings from Master Key Providers:
    #. Migration example to AWS KMS keyring from AWS KMS Master Key Provider.
    #. Migration example to Raw AES keyring from Raw AES Master Key Provider.
    #. Migration example to Raw RSA keyring from Raw RSA Master Key Provider.
    
* Migration to newer versions of the ESDK from the old version (1.x):
    #. Setting a 'CommitmentPolicy' during migration.
    If you have messages encrypted in the older versions of the ESDK (1.x),
    this example can guide you on how to decrypt those messages using the
    new version of the ESDK.

.. _AWS Cryptographic Material Providers Library: https://github.com/aws/aws-cryptographic-material-providers-library
.. _Encryption SDK for Python: https://github.com/aws/aws-encryption-sdk-python/tree/9c34aad60fc918c1a9186ec5215a451e8bfd0f65