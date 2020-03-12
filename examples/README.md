# AWS Encryption SDK Examples

This section features examples that show you
how to use the AWS Encryption SDK.
We demonstrate how to use the encryption and decryption APIs
and how to set up some common configuration patterns.

## APIs

The AWS Encryption SDK provides two high-level APIs:
one-step APIs that process the entire operation in memory
and streaming APIs.

You can find examples that demonstrate these APIs
in the [`examples/src/`](./src) directory.

## Configuration

To use the library APIs,
you need to describe how you want the library to protect your data keys.
You can do this using
[keyrings](#keyrings) or [cryptographic materials managers](#cryptographic-materials-managers),
or using [master key providers](#master-key-providers).
These examples will show you how.

### Keyrings

Keyrings are the most common way for you to configure the AWS Encryption SDK.
They determine how the AWS Encryption SDK protects your data.
You can find these examples in [`examples/src/keyring`](./src/keyring).

* AWS KMS keyring
    * [How to use the KMS keyring with a single CMK](./src/keyring/aws_kms/single_cmk.py)
    * [How to use the KMS keyring with multiple CMKs in different regions](./src/keyring/aws_kms/multiple_regions.py)
    * [How to use the KMS keyring in discovery mode](./src/keyring/aws_kms/discovery_decrypt.py)
    * [How to restrict the KMS discovery keyring to a single region](./src/keyring/aws_kms/discovery_decrypt_in_region_only.py)
    * [How to prefer the local AWS region but fail over to others with the KMS discovery keyring](./src/keyring/aws_kms/discovery_decrypt_with_preferred_regions.py)
* Multi-keyring
    * [How to combine AWS KMS with an offline escrow key](./src/keyring/multi/aws_kms_with_escrow.py)
* Raw keyrings
    * [How to use the Raw AES keyring](./src/keyring/raw_aes/raw_aes.py)
    * [How to use the Raw RSA keyring](./src/keyring/raw_rsa/private_key_only.py)
    * [How to use the Raw RSA keyring with PEM or DER encoded keys](./src/keyring/raw_rsa/private_key_only_from_pem.py)
    * [How to use the Raw RSA keyring to encrypt with only the public key](./src/keyring/raw_rsa/public_private_key_separate.py)

### Cryptographic Materials Managers

Keyrings define how your data keys are protected,
but there is more going on here than just protecting data keys.

Cryptographic materials managers give you higher-level controls
over how the AWS Encryption SDK protects your data.
This can include things like
enforcing the use of certain algorithm suites or encryption context settings,
reusing data keys across messages,
or changing how you interact with keyrings.
You can find these examples in
[`examples/src/crypto_materials_manager`](./src/crypto_materials_manager).

### Master Key Providers

Before there were keyrings, there were master key providers.
Master key providers were the original configuration structure
that we provided for defining how you want to protect your data keys.
Keyrings provide a simpler experience and often more powerful configuration options,
but if you need to use master key providers,
need help migrating from master key providers to keyrings,
or simply want to see the difference between these configuration experiences,
you can find these examples in [`examples/src/master_key_provider`](./src/master_key_provider).

## Legacy

This section includes older examples, including examples of using master keys and master key providers in Java and Python.
You can use them as a reference,
but we recommend looking at the newer examples, which explain the preferred ways of using this library.
You can find these examples in [`examples/src/legacy`](./src/legacy).

# Writing Examples

If you want to contribute a new example, that's awesome!
To make sure that your example is tested in our CI,
please make sure that it meets the following requirements:

1. The example MUST be a distinct module in the [`examples/src/`](./src) directory.
1. The example MAY be nested arbitrarily deeply,
    but every intermediate directory MUST contain a `__init__.py` file
    so that CPython 2.7 will recognize it as a module.
1. Every example MUST be CPython 2.7 compatible.
1. Each example file MUST contain exactly one example.
1. Each example file MUST contain a function called `run` that runs the example.
1. If your `run` function needs any of the following inputs,
    the parameters MUST have the following names:
    * `aws_kms_cmk` (`str`) : A single AWS KMS CMK ARN.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:GenerateDataKey`, `kms:Encrypt`, and `kms:Decrypt` permissions on this CMK.
    * `aws_kms_generator_cmk` (`str`) : A single AWS KMS CMK ARN to use as a generator key.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:GenerateDataKey`, `kms:Encrypt`, and `kms:Decrypt` permissions on this CMK.
    * `aws_kms_additional_cmks` (`List[str]`) :
        A list of AWS KMS CMK ARNs to use for encrypting and decrypting data keys.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:Encrypt` and `kms:Decrypt` permissions on these CMKs.
    * `source_plaintext` (`bytes`) : Plaintext data to encrypt.
    * `source_plaintext_filename` (`str`) : A path to a file containing plaintext to encrypt.
        * NOTE: You can assume that you have write access to the parent directory
            and that anything you do in that directory will be cleaned up
            by our test runners.
1. Any additional parameters MUST be optional.
