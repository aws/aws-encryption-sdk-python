# AWS Encryption SDK Examples

Here you can find some examples that show you
how to use the AWS Encryption SDK.
We demonstrate how to use the high-level APIs
as well as how to set up some common configuration patterns.

## APIs

The AWS Encryption SDK provides two high-level APIs:
one-shot APIs that process the entire operation in memory
and streaming APIs.

You can find examples that demonstrate these APIs
in the [`examples/src/`](./src) directory root.

## Configuration

In order to use the library APIs,
you must provide some configuration that defines
how you want to protect your data keys.

### Keyrings

Keyrings are the most common way for you to configure that AWS Encryption SDK.
These let you define how you want the AWS Encryption SDK to protect your data keys.
You can find these examples in [`examples/src/keyring`](./src/keyring).

### Cryptographic Materials Managers

Keyrings define how you want to protect your data keys,
but there is more going on here than just data keys.

Cryptographic materials managers give you higher-level controls
over how the AWS Encryption SDK protects your data.
This can include things like
enforcing certain algorithm suites or encryption context settings,
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

These are any examples that were already defined
before we started revamping our examples.
We are keeping them around for anyone who needs them as reference material,
but we recommend looking at the newer examples
that should provide a clearer picture of how to use this library.
You can find these examples in [`examples/src/legacy`](./src/legacy).

# Writing Examples

If you want to write a new example, that's awesome!
There are a couple things you need to keep in mind, though.
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
    * `aws_kms_cmk_arn` (`str`) : A single AWS KMS CMK ARN.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:GenerateDataKey`, `kms:Encrypt`, and `kms:Decrypt` permissions on this CMK.
    * `aws_kms_generator_cmk` (`str`) : A single AWS KMS CMK ARN to use as a generator key.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:GenerateDataKey`, `kms:Encrypt`, and `kms:Decrypt` permissions on this CMK.
    * `aws_kms_child_cmks` (`List[str]`) : A list of AWS KMS CMK ARNs to use as child keys.
        * NOTE: You can assume that automatically discovered credentials have
            `kms:Encrypt` and `kms:Decrypt` permissions on these CMKs.
    * `source_plaintext` (`bytes`) : Plaintext data to encrypt.
    * `source_plaintext_filename` (`str`) : A path to a file containing plaintext to encrypt.
        * NOTE: You can assume that you have write access to the parent directory
            and that anything you do in that directory will be cleaned up
            by our test runners.
1. Any additional parameters MUST be optional.
