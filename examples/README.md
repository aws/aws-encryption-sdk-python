# AWS Encryption SDK Examples

Here you can find some examples that show you
how to use the AWS Encryption SDK.
We demonstrate how to use the high-level APIs
as well as how to set up some common configuration patterns.

## APIs

The AWS Encryption SDK provides two high-level APIS:
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
[`examples/src/crypto_materials_managers`](./src/crypto_materials_manager).

### Master Key Providers

Before there were keyrings, there were master key providers.
Master key providers were the original configuration structure
that we defined for defining how you want to protect your data keys.
Keyrings provide a simpler experience and often more powerful configuration options,
but if you need to use master key providers,
need help migrating from master key providers to keyrings,
or simply want to see the difference between these configuration experiences,
you can find these examples in [`examples/src/master_key_provider`](./src/master_key_provider).

## Legacy

The examples in [`examples/src/legacy`](./src/legacy).
