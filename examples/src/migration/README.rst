##################
Migration Examples
##################

The native Python ESDK now uses the `AWS Cryptographic Material Providers Library`_,
which introduces keyrings in place of the Master Key Provider. The MPL abstracts lower
level cryptographic materials management of encryption and decryption materials.

This directory contains some examples to migrate from the legacy Master Key Providers
to keyrings. Here is the list of examples:
1. Migration to AWS KMS Keyring from AWS KMS Master Key Provider
2. Migration to Raw AES Keyring from Raw AES Master Key Provider
3. Migration to Raw RSA Keyring from Raw RSA Master Key Provider
4. Setting a 'CommitmentPolicy' during migration

.. _AWS Cryptographic Material Providers Library: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html