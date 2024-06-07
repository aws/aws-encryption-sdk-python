##################
Migration Examples
##################

The `Encryption SDK for Python`_ now uses the `AWS Cryptographic Material Providers Library`_,
which introduces keyrings in place of Master Key Providers. The MPL abstracts lower
level cryptographic materials management of encryption and decryption materials.

This directory contains some examples to migrate from the old version of the ESDK.
If you have messages encrypted in the older versions using Master Key Providers,
these examples can guide you on how to decrypt those messages using the new version
of the ESDK. Here is the list of examples:
1. Migration example for AWS KMS keys
2. Migration example for Raw AES keys
3. Migration example for Raw RSA keys
4. Setting a 'CommitmentPolicy' during migration

.. _AWS Cryptographic Material Providers Library: https://github.com/aws/aws-cryptographic-material-providers-library
.. _Encryption SDK for Python: https://github.com/aws/aws-encryption-sdk-python/tree/9c34aad60fc918c1a9186ec5215a451e8bfd0f65