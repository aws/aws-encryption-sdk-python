[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: Apache-2.0"

# Multi-Tenant AWS KMS Clients for the AWS Encryption SDK for Python

# Definitions

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

## Tenant

A customer of an application built with the AWS Encryption SDK for Python (ESDK-Python),
whose data is protected by a KMS Key that belongs to,
or is dedicated to,
that customer.

## Tenant Credentials

The AWS Credentials an application MUST use when calling KMS on behalf of a Tenant.

These are usually obtained by an `sts:AssumeRole` of a Tenant specific IAM Role,
such that the Tenant's KMS Key Policy can grant access to that role,
and only that role.

In this document,
Tenant Credentials are any `botocore.credentials.Credentials`,
including `RefreshableCredentials`.

## Heavy Object

An object whose construction cost (time, memory)
or retained resources (connection pools, TLS sessions, event emitters, loggers)
make it unreasonable to construct one per Tenant
when an application serves hundreds or thousands of Tenants.

## Shared Transport

`KmsTransport`, defined in [kms_transport.py](./kms_transport.py).

One per process.
It owns the only HTTP connection pool,
signs every request with SigV4,
retries,
and maps failures to botocore's exception types.

## AWS KMS Key Store

The MPL's `KeyStore`
(`aws_cryptographic_material_providers.keystore`),
which persists the Branch Keys used by the AWS KMS Hierarchical Keyring.

## Tenant KMS Client

`TenantKmsClient`, defined in [tenant_kms_client.py](./tenant_kms_client.py).

One per Tenant per AWS Region.
It holds a reference to the Shared Transport,
a region,
and the Tenant Credentials;
nothing else.
It exposes the subset of the boto3 KMS client's interface
that the ESDK-Python and
the AWS Cryptographic Material Providers Library (MPL) use.

## KMS Operations in Scope

| Operation                             | Used by                                                                              |
| ------------------------------------- | ------------------------------------------------------------------------------------ |
| `kms:GenerateDataKey`                 | AWS KMS Keyring, KMS Master Keys (encrypt)                                           |
| `kms:Encrypt`                         | AWS KMS Keyring, KMS Master Keys (encrypt, additional KMS Keys)                      |
| `kms:Decrypt`                         | AWS KMS Keyring, KMS Master Keys (decrypt), AWS KMS Key Store (`GetActiveBranchKey`) |
| `kms:GenerateDataKeyWithoutPlaintext` | AWS KMS Key Store (`CreateKey`, `VersionKey`)                                        |
| `kms:ReEncrypt`                       | AWS KMS Key Store (`CreateKey`, `VersionKey`)                                        |

# Background

The ESDK-Python's Master Key Providers (MKPs) and the MPL's Keyrings
call KMS through a boto3 KMS client.

boto3 binds AWS Credentials to a client when the client is constructed.
Thus,
an application that MUST call KMS with a different set of credentials per Tenant
needs at least one KMS client per Tenant,
and an MKP needs at least one botocore Session per Tenant.

Each of those is a Heavy Object (see [Design Question 1](#1-are-boto3-sessions-and-kms-clients-heavy-objects)).

This is not a problem in Java.
The AWS SDK for Java V2 allows credentials to be overridden per request
(`AwsRequestOverrideConfiguration#credentialsProvider`);
combined with the fact that `KmsClient` is an interface,
an application can wrap one KMS client per Tenant
around a single shared client,
where each wrapper overrides the credentials of every request.
The shared client owns the only HTTP client,
credential cache,
and logger.

The AWS SDK for Python (boto3) does not afford the same.

This document records the options considered,
and the decisions made,
for an example that lets an ESDK-Python application
call KMS with per-Tenant credentials
while sharing one HTTP connection pool,
one signer,
and one logger across all Tenants.

# Requirements

1. All Tenants in a process MUST share one HTTP connection pool, one signer, and one logger.

2. Every KMS request MUST be signed with the requesting Tenant's Credentials,
   and MUST NOT be signed with any other Tenant's Credentials.

3. Refreshable Tenant Credentials MUST be refreshed;
   i.e: credentials from `sts:AssumeRole` keep working after they expire.

4. The example MUST support:
   - the AWS KMS Keyring, including keyrings built with a Client Supplier
   - the AWS KMS Hierarchical Keyring's AWS KMS Key Store
   - the Strict, Discovery, and MRK-aware KMS Master Key Providers

5. The example MUST support the [KMS Operations in Scope](#kms-operations-in-scope).

6. The Shared Transport and the Tenant KMS Client MUST work on every Python version the ESDK-Python supports (3.8+),
   and MUST NOT import the MPL,
   as the legacy MKP examples run without the MPL installed.

7. The Shared Transport SHOULD depend only on public, documented botocore interfaces.

# Out of Scope

- Full boto3 parity:
  any KMS operation not listed in [KMS Operations in Scope](#kms-operations-in-scope),
  paginators,
  waiters,
  and the `Recipient` (Nitro Enclave attestation) parameter.
- botocore's endpoint resolution (FIPS, dual-stack, partitions other than `aws` and `aws-cn`);
  an endpoint override is offered instead.
- botocore's adaptive retry mode and its client side rate limiting.
- HTTP(S) proxies;
  boto3 honors `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY`,
  but the Shared Transport ignores them.
  An application behind a proxy MUST NOT use this example as written;
  its KMS requests will fail to connect (or time out) rather than fail with a proxy error.
- Sourcing Tenant Credentials (STS, credential caching);
  the example accepts any `botocore.credentials.Credentials`.
- Per-Tenant DynamoDB credentials for the AWS KMS Key Store.
- Changes to the ESDK-Python, the MPL, or boto3.

## Why not change the ESDK-Python or the MPL?

The cleanest fix is for the libraries themselves
to accept a per-Tenant credential override.

For the MPL,
that is a change to the Smithy model,
the Dafny implementation,
and every runtime's shim;
for the ESDK-Python's MKPs,
it is a public API change.

An example can ship now,
needs no release,
and its usage can inform such a feature.

## Why not per-Tenant DynamoDB credentials?

The AWS KMS Key Store's isolation boundary is the Tenant's KMS Key;
a Branch Key Item is useless without `kms:Decrypt` on the KMS Key that protects it.

The AWS KMS Hierarchy Keyring is designed as a multi-tenant solution
predicated on KMS being the isolation boundary, not DynamoDB.

The Branch Keys of the AWS KMS Key Store are a shared resource between
the tenants and the service/application protecting the tenants data under KMS.

## Which non-public interfaces does the example depend on?

**botocore**:  
None.
The Shared Transport and Tenant KMS Client use
`botocore.auth.SigV4Auth`,
`botocore.awsrequest.AWSRequest`,
`botocore.credentials.Credentials.get_frozen_credentials`,
and `botocore.exceptions`.
botocore does not formally document a public API;
these are the interfaces customers commonly use to sign their own requests,
and they have been stable for many years.

**MPL**:  
None.
However,
the example relies on the MPL duck typing its `kms_client`
([4.1](#41-keyrings-client-suppliers-and-the-aws-kms-key-store)),
which is behavior rather than an interface.

**ESDK-Python**:  
Yes.
The MKP subclasses override or use protected members of the KMS Master Key Providers:
`_config_class`,
`_regional_clients`,
`_register_client`,
and `_user_agent_adding_config`;
and the MRK-aware Discovery MKP subclass overrides `_new_master_key_impl`
and imports `aws_encryption_sdk.internal.arn`
([4.2.2](#422-relax-the-validator-with-configuration-subclasses)).

These members are from the legacy MKP code base,
which is unlikely to be refactored,
as Crypto Tools is moving to Keyrings everywhere
being the only supported interface.
Thus,
the risk is accepted.

# Design Questions

## 1 Are boto3 Sessions and KMS clients Heavy Objects?

Yes.

The author measured constructing 50 KMS clients per pattern
with `tracemalloc` and no network calls
(Python 3.14, boto3 & botocore 1.43.114):

| Pattern                                             | Time each | Memory each |
| --------------------------------------------------- | --------- | ----------- |
| `boto3.Session(credentials)` only                   | 49 ms     | 142 KiB     |
| New Session and KMS client per Tenant               | 239 ms    | 8.4 MiB     |
| One shared Session, `session.client("kms", ...)` per Tenant | 9.6 ms | 176 KiB |

**A Session per Tenant does not scale**:  
At ~8 MiB each,
1,000 Tenants is ~8 GiB of resident memory before a single request is made.

**A shared Session helps, but not enough**:  
The shared Session caches the parsed service model,
which is most of the cost.
However,
every client still constructs its own `urllib3` connection pool
(`client._endpoint.http_session`)
and its own event emitter (`client.meta.events`);
the author confirmed neither is shared between clients.

Thus,
Tenants never re-use each other's TLS connections,
and every Tenant pays its own TLS handshake to KMS.
The 176 KiB above does not include live sockets or TLS state,
so the true cost is higher.

Finally,
MKPs do not accept a client;
they accept a Session.
Sharing one Session across Tenants is not possible,
as the Session carries the credentials.

## 2 Does boto3 offer per-request credentials?

### 2.1 Public interface

No.

Credentials are bound to the client's `RequestSigner` at construction
(`botocore/client.py`, `BaseClient._get_credentials` returns `self._request_signer._credentials`).

Every operation validates its parameters against the KMS service model;
passing `aws_access_key_id=`, `credentials=`, `Credentials=`, or `config=`
to an operation raises `botocore.exceptions.ParamValidationError`.

There is no equivalent to Java's `overrideConfiguration` in boto3; however, the AWS SDK for Python v4 may introduce a solution.

### 2.2 The private `request_credentials` signing context

botocore's `RequestSigner.sign` reads
`request.context["signing"]["request_credentials"]`
and,
if present,
uses those credentials instead of the client's
(`botocore/signers.py`: `credentials = request_credentials or self._credentials`).

No public interface sets this key;
but a handler registered on the client's `before-sign.kms` event can.

The author confirmed that one client,
with a `before-sign.kms` handler that reads the current Tenant from a `contextvars.ContextVar`,
signs consecutive requests with three different access keys.

**Pro, the least code**:  
The application keeps boto3's retries,
error types,
endpoint resolution,
and everything else,
for the cost of one event handler.

**Con, it is private**:  
`request_credentials` is not documented,
appears nowhere else in botocore,
and MAY change in any release without notice.
An example that customers copy into production
SHOULD NOT depend on it.

**Con, it bypasses credential refresh**:  
The client's normal path calls `get_frozen_credentials()`;
the override path signs with whatever object it is given.
The application would need to freeze `RefreshableCredentials` itself.

**Con, Tenant routing via ambient state**:  
Which Tenant a request is for
is determined by a context variable,
not by the object the ESDK-Python or MPL is holding.
A missed `reset` signs a request with the wrong Tenant's Credentials,
violating Requirement 2;
this is a confused deputy waiting to happen.

UPDATE: Rejected as the recommended path.
It remains a reasonable,
if fragile,
option for applications that already pin botocore.

### 2.3 Author's conclusion

boto3 has no public interface for per-request credentials
([2.1](#21-public-interface));
the only path is private
([2.2](#22-the-private-request_credentials-signing-context)).

Thus,
the example pursues other options
(see [Design Question 3](#3-where-do-we-inject-the-per-tenant-behavior)).

## 3 Where do we inject the per-Tenant behavior?

The ESDK-Python's MKPs accept a `botocore.session.Session`;
the MPL's Keyrings and AWS KMS Key Store accept a KMS client.
Neither accepts a connection pool.

### 3.1 A custom Master Key Provider and Keyring

Write a new MKP and a new Keyring that call KMS with a shared transport.

**Con, re-implementing verified logic**:  
The AWS KMS Keyring's behavior
(Encrypted Data Key filtering,
KMS Key ARN and MRK matching,
discovery filters)
is specified,
and in the MPL,
implemented in Dafny and verified.
A custom Keyring re-implements all of it,
in Python,
unverified,
to change only how KMS is called.

**Con, the Hierarchical Keyring needs a custom AWS KMS Key Store too**:  
The Hierarchical Keyring calls KMS through the AWS KMS Key Store,
not directly.
A custom Keyring does nothing for it;
this option also requires a custom AWS KMS Key Store,
which is one more component to write, test, and maintain,
where [3.3](#33-a-lightweight-boto3-shaped-kms-client-over-a-shared-transport) requires none.

**Con, two of everything**:  
The same applies to the four MKPs.

### 3.2 Extend `botocore.session.Session`

Subclass the Session such that `create_client`
returns something lighter.

**Con, Keyrings never see a Session**:  
This does nothing for the MPL.

**Con, the result MUST still be a `BaseClient`**:  
See [4.2](#42-master-key-providers).

**Con, the Session is the Heavy Object**:  
The Session's surface is large
(credential resolver,
loaders,
configuration chain,
event system,
component registry);
and per [Design Question 1](#1-are-boto3-sessions-and-kms-clients-heavy-objects)
the Session is a significant part of the cost.
As the Session carries the credentials,
there would still be one per Tenant.

### 3.3 A lightweight, boto3 shaped, KMS client over a Shared Transport

Leave the MKPs,
Keyrings,
and AWS KMS Key Store alone.
Replace only the KMS client they are given.

The Shared Transport owns the connection pool,
the SigV4 signer (`botocore.auth.SigV4Auth`, a public interface),
retries,
and the logger.
The Tenant KMS Client is a few references
and five methods
that accept and return what boto3's methods accept and return.

**Pro, nothing verified is re-implemented**:  
Every Keyring,
the AWS KMS Key Store,
and every MKP behave exactly as they do with boto3.

**Pro, one artifact serves both**:  
The same Tenant KMS Client is handed to a Keyring,
a Client Supplier,
an AWS KMS Key Store,
or an MKP.

**Con, a small KMS client to maintain**:  
Five operations,
basic retries,
and error mapping.
This is the cost of Requirements 1 and 2.

### 3.4 Author's conclusion

3.3.

## 4 How does a Tenant KMS Client satisfy the ESDK-Python and the MPL?

### 4.1 Keyrings, Client Suppliers, and the AWS KMS Key Store

The MPL types `kms_client` as `botocore.client.BaseClient`;
this is a type hint,
not a runtime check.

All three routes
(`CreateAwsKmsKeyringInput.kms_client`,
`IClientSupplier.get_client`,
and `KeyStoreConfig.kms_client`)
pass the object to the same extern,
`Com_Amazonaws_Kms.KMSClient`,
which wraps it in a `KMSClientShim`.

The shim only:

- calls the boto3 method by its snake case name, with boto3 shaped keyword arguments (e.g: `generate_data_key(KeyId=..., ...)`)
- catches `botocore.exceptions.ClientError`, and maps it by `e.response["Error"]["Code"]` and `e.response["Error"]["Message"]`
- reads `meta.region_name`
- appends to `meta.config.user_agent_extra`

The author confirmed an ESDK-Python encrypt and decrypt,
through `create_aws_kms_keyring`,
with a plain Python object that is not a `BaseClient`.

**Risk, duck typing is not a contract**:  
A future MPL MAY add a runtime `isinstance` check.
The example's tests will detect that;
there is no mitigation short of [3.1](#31-a-custom-master-key-provider-and-keyring).

### 4.2 Master Key Providers

`KMSMasterKeyConfig.client` and `MRKAwareKMSMasterKeyConfig.client`
are validated with `attr.validators.instance_of(botocore.client.BaseClient)`.

#### 4.2.1 Subclass `BaseClient`, skip `__init__`

Make the Tenant KMS Client a `BaseClient` subclass,
and never call `BaseClient.__init__`.

Rejected;
the object would claim to be something it is not,
and any ESDK-Python code path that touches a `BaseClient` attribute we did not anticipate
fails with an `AttributeError` far from the cause.

#### 4.2.2 Relax the validator with configuration subclasses

Subclass `KMSMasterKeyConfig` and `MRKAwareKMSMasterKeyConfig`,
overriding only `client`,
with a validator that checks for the KMS methods the Master Keys call.

`MasterKey.__new__` checks `isinstance(config, _config_class)`,
so a subclass of the expected configuration is accepted.

Subclass each of the four MKPs,
setting `master_key_config_class` to the matching configuration subclass,
and overriding `add_regional_client`
(the extension point the existing
[legacy custom KMS client example](../legacy/custom_kms_client_for_kms_provider.py)
already uses).

The MKP's `_register_client` only needs `client.meta.method_to_api_mapping`
and methods it can replace with `setattr`;
the Tenant KMS Client offers both,
so `_wrap_client`,
and its eviction of a regional client on `BotoCoreError`,
work unchanged.

The Shared Transport and Tenant Credentials reach `add_regional_client`
through a subclass of `KMSMasterKeyProviderConfig`,
as `MasterKeyProvider.__new__` passes every keyword argument to the configuration class.

**The MRK-aware Discovery MKP ignores `master_key_config_class`**:  
`MRKAwareDiscoveryAwsKmsMasterKeyProvider._new_master_key_impl`
constructs `MRKAwareKMSMasterKeyConfig` directly,
in both of its branches.
Thus its subclass MUST also override `_new_master_key_impl`;
the override repeats the parent's logic
(a multi-Region key is used in the discovery Region,
any other key in the Region of its ARN)
and only substitutes the configuration class.
This was found by the example's tests, not by reading;
which is an argument for the tests.

_Note_: The ESDK-Python supports `attrs>=17.4.0`,
which predates `kw_only`.
The overridden and added attributes therefore default to `None`
and are validated as required.

#### 4.2.3 Author's conclusion

4.2.2.

### 4.3 MKPs construct a Session per provider by default

If no `botocore_session` is given,
`KMSMasterKeyProviderConfig` constructs a new `botocore.session.Session()`
for every MKP.

With per-Tenant MKPs,
that is one Heavy Object per Tenant,
even though the Tenant KMS Client never uses it.

The example MUST pass one shared `botocore_session` to every MKP.

## 5 What errors does the Tenant KMS Client raise?

Exactly what boto3 would.

**Service errors**:  
`botocore.exceptions.ClientError`,
with `response["Error"]["Code"]` stripped of any namespace
(KMS MAY return `com.amazonaws.kms#NotFoundException`;
the MPL expects `NotFoundException`),
`response["Error"]["Message"]`,
and `response["ResponseMetadata"]`.

**Transport failures**:  
After the final attempt,
the exception botocore's `URLLib3Session.send` (`botocore/httpsession.py`)
would raise for the same urllib3 failure,
checked in the same order:

| urllib3                                        | botocore                  |
| ---------------------------------------------- | ------------------------- |
| `SSLError`                                     | `SSLError`                |
| `NewConnectionError` (incl. `NameResolutionError`) | `EndpointConnectionError` |
| `ConnectTimeoutError`                          | `ConnectTimeoutError`     |
| `ReadTimeoutError`                             | `ReadTimeoutError`        |
| `ProtocolError`                                | `ConnectionClosedError`   |
| any other exception                            | `HTTPClientError`         |

`concurrent.futures.CancelledError` is re-raised unwrapped,
as botocore does.
botocore also maps urllib3's `ProxyError`;
proxies are [Out of Scope](#out-of-scope),
so it cannot occur.

All are `BotoCoreError`s,
which the MKPs rely on to evict a regional client.

**Invalid parameters**:  
`botocore.exceptions.ParamValidationError`,
raised before any request is made.

## 6 Retries

Basic,
modeled on botocore's `standard` mode:

- at most `max_attempts` (default 3) attempts
- retry the transport failures botocore's standard mode treats as transient
  (`ConnectionError` and `HTTPClientError`, per `TransientRetryableChecker` in `botocore/retries/standard.py`);
  i.e: every transport failure in [5](#5-what-errors-does-the-tenant-kms-client-raise),
  but never `NoCredentialsError`
- retry HTTP 5xx, `ThrottlingException`, `KMSInternalException`, and `DependencyTimeoutException`
- never retry any other 4xx
- full jitter exponential backoff, capped at 20 seconds
- every attempt is re-signed, as the SigV4 signature is time bound and Refreshable Credentials MAY have rotated

botocore's retry quota (token bucket) and adaptive mode are [Out of Scope](#out-of-scope).

## 7 Endpoints

**Default**:  
`https://kms.{region}.amazonaws.com`,
or `https://kms.{region}.amazonaws.com.cn` for `cn-*` Regions.

**Override**:  
The Tenant KMS Client accepts an `endpoint_url`,
as boto3's clients do.
MKPs and the Client Supplier accept `endpoint_urls`,
a mapping of Region to URL,
as they construct clients for Regions they discover at runtime.

**The Region MUST be validated**:  
A Discovery Keyring or Discovery MKP takes the Region
from the KMS Key ARN in the message's Encrypted Data Keys;
i.e: from the ciphertext.
A crafted ARN whose "Region" is `evil.example.com/` would otherwise
direct a signed request,
with Tenant Credentials in its signature scope,
to a host the attacker controls.

The Shared Transport MUST reject any Region that is not
lowercase letters, digits, and hyphens.

## 8 Tenant Credentials

The Tenant KMS Client calls `credentials.get_frozen_credentials()` on every attempt;
this is what refreshes `RefreshableCredentials`.

Tenant Credentials MUST NOT appear in logs or in any `repr`;
the Tenant KMS Client's `repr` names only its Region and endpoint.
The ESDK-Python's `attrs` configurations include the client in their `repr`,
which makes this a requirement rather than a courtesy.

Request and response bodies contain plaintext data keys,
and MUST NOT be logged.

## 9 Thread safety

The Shared Transport is safe to share across threads;
`urllib3.PoolManager` is thread safe,
and the transport holds no other mutable state.

The Tenant KMS Client is immutable,
with one exception:
the MPL appends its user agent to `meta.config.user_agent_extra`
when a Keyring or AWS KMS Key Store is constructed.
That is a check then append on a string;
the worst case of a race is the suffix appearing twice.

## 10 The Hierarchical Keyring

Each Tenant gets an AWS KMS Key Store,
constructed with that Tenant's Tenant KMS Client
and the shared DynamoDB client,
and a Hierarchical Keyring on that AWS KMS Key Store.

The AWS KMS Key Store calls KMS only to create or version a Branch Key,
and to decrypt a Branch Key on a cache miss;
thus the KMS request rate per Tenant is low,
but Requirement 2 still applies to every request.

### 10.1 One shared cache

Every Tenant's Hierarchical Keyring is given the same cache
(`CacheTypeShared`, wrapping one `create_cryptographic_materials_cache`),
rather than a cache per keyring.

The cache is a storm tracking cache:
as a cached Branch Key nears expiry,
one request refreshes it while the others keep using the cached entry,
and its fan out caps how many distinct Branch Keys are fetched at once.
A cache per keyring applies that cap per Tenant;
a shared cache applies it across all Tenants,
which is where a thundering herd comes from.
One entry capacity also bounds the memory of every Tenant's cached Branch Keys,
rather than one bound per Tenant.

### 10.1.1 Why not the MPL's `DefaultCache`?

`DefaultCache` is a storm tracking cache with the MPL's default parameters
(`StormTracker.DefaultStorm()`);
those defaults suit a cache per keyring,
and two of them do not suit a cache shared by every Tenant.

**The fan out is now a process wide limit**:  
Once fan out (default 20) distinct Branch Keys are being fetched,
a caller whose Branch Key has no cached entry blocks.
Shared by every Tenant,
20 would serialize a burst of Tenants missing the cache at once,
such as at startup,
or when Branch Keys created together expire together.

**A failing Tenant holds fan out slots**:  
The Hierarchical Keyring only marks a fetch complete
(`PutCacheEntry`)
when the fetch succeeds;
a failed fetch holds its fan out slot until the in flight TTL (default 10 seconds) expires.
A Tenant whose fetches fail,
such as with revoked credentials,
would hold slots the other Tenants need.
Sharing the cache made this a cross Tenant concern.

**A units trap**:  
`DefaultStorm()` uses milliseconds;
a `StormTrackingCache` constructed by hand defaults to seconds.
Copying the default values without also setting `time_units`
turns a 10 second grace period into roughly 2.8 hours.

Thus,
the example sets every parameter explicitly,
documenting why in the source:

| Parameter                 | Example        | MPL default | Why                                                              |
| ------------------------- | -------------- | ----------- | ---------------------------------------------------------------- |
| `entry_capacity`          | 1000           | 1000        | Size for every Tenant's Branch Keys, not one Tenant's            |
| `entry_pruning_tail_size` | 1              | 1           | Default                                                          |
| `grace_period`            | 10,000 ms      | 10,000 ms   | Default; short relative to the keyrings' 600 second TTL          |
| `grace_interval`          | 1,000 ms       | 1,000 ms    | Default                                                          |
| `fan_out`                 | 100            | 20          | Do not serialize a burst of Tenants missing the cache at once    |
| `in_flight_ttl`           | 5,000 ms       | 10,000 ms   | Release a failing Tenant's slots sooner                          |
| `sleep_milli`             | 20 ms          | 20 ms       | Default                                                          |
| `time_units`              | `MILLISECONDS` | seconds     | MUST be set explicitly; see the units trap                       |

The MPL requires `grace_interval <= in_flight_ttl <= grace_period`.
The in flight TTL SHOULD exceed a typical DynamoDB plus KMS fetch,
including retries;
a fetch that takes longer MAY be duplicated by another request.

These values are illustrative.
Applications SHOULD tune every one of them to their own usage pattern:
the number of Tenants,
how many Tenants miss the cache at once,
Branch Key TTLs,
and DynamoDB and KMS latency.

_Note_: The MPL's specification
(`changes/2023-06-19_thread_safe_cache/change.md`)
gives the in flight TTL a default of 20 seconds;
the implementation's default is 10 seconds.

### 10.1.2 Requires MPL 1.11.3 or later

The ESDK-Python allows `aws-cryptographic-material-providers` from 1.7.4.
Before 1.11.3,
the Python runtime's storm tracking cache passed `sleep_milli` to `time.sleep`,
which takes seconds
([aws-cryptographic-material-providers-library#1940](https://github.com/aws/aws-cryptographic-material-providers-library/issues/1940));
with the defaults,
a blocked caller slept 20 seconds per check, rather than 20 milliseconds.
The example therefore requires 1.11.3 or later.

Keyrings share cache entries only if their
Partition ID,
Logical Key Store Name,
and Branch Key ID
are all the same.
Every Tenant's AWS KMS Key Store is an instance of the same physical Key Store,
and so has the same Logical Key Store Name;
Tenants are separated by their Branch Key IDs,
and additionally by their Partition IDs.

### 10.2 The Partition ID

The Partition ID is the SHA-384 digest of the Tenant's secret access key.

**It is distinct per Tenant**:  
Different credentials have different secret access keys,
so Tenants are isolated within the shared cache
even if a Branch Key ID were ever reused or misconfigured.

**It is not the secret**:  
The MPL digests the Partition ID into every cache identifier;
however,
the Hierarchical Keyring keeps its Partition ID,
unhashed,
for its lifetime.
Using the secret access key directly would leave another copy of the secret in memory.
The example therefore digests it first;
a digest of a high entropy secret discloses nothing useful.

**It changes when credentials are refreshed**:  
Refreshable Tenant Credentials (i.e: `sts:AssumeRole`) rotate the secret access key.
A keyring created after a refresh has a different Partition ID,
so it does not share cache entries with a keyring created before the refresh,
and its first use of a Branch Key is a cache miss.

This is intended;
it ties a Tenant's cache usage to the lifetime of its credentials.
A keyring created before a refresh keeps its Partition ID,
and keeps using its cache entries until they expire;
its cache misses are fetched with the refreshed credentials,
as the Tenant KMS Client freezes credentials on every request.

### 10.3 Shutdown

The Shared Transport and the DynamoDB client are both shared by every Tenant;
the example closes both,
and an application MUST close them only when it shuts down.
Closing either while a Tenant may still use it drops every pooled connection,
and costs every Tenant a new TLS handshake.

_Note_: If Tenants do not require distinct KMS credentials,
one AWS KMS Key Store and a Branch Key ID Supplier
(see [branch_key_id_supplier_example.py](../branch_key_id_supplier_example.py))
is the simpler multi-tenant design,
and this example is unnecessary.

# Consequences

- The keyring path depends on the MPL duck typing its `kms_client` ([4.1](#41-keyrings-client-suppliers-and-the-aws-kms-key-store)).
- The MKP path depends on the ESDK-Python's `add_regional_client`, `_register_client`, `_regional_clients`, and `_user_agent_adding_config`;
  these are protected members,
  but are already used by the legacy custom KMS client example.
- The MRK-aware Discovery MKP subclass duplicates `_new_master_key_impl`,
  and imports `aws_encryption_sdk.internal.arn`;
  a change to the parent's logic MUST be mirrored ([4.2.2](#422-relax-the-validator-with-configuration-subclasses)).
- Retries are less sophisticated than botocore's ([6](#6-retries)).
- Endpoint resolution is a template, not botocore's resolver ([7](#7-endpoints)).

# Validation

**Offline**:  
`examples/test/multi_tenant/` and `examples/test/legacy/test_multi_tenant_kms_master_key_provider.py`
replace the Shared Transport's connection pool with an in-memory KMS
that authorizes each KMS Key for exactly one access key.
They run the examples themselves,
every Keyring and MKP variant,
and every [KMS Operation in Scope](#kms-operations-in-scope),
and assert which access key signed every request;
i.e: Requirement 2 is tested, not assumed.

**Against AWS KMS**:  
The AWS KMS Keyring and MKP examples pass.
Five requests,
signed with two different sets of credentials,
were sent over one TLS connection (Requirement 1);
the unrecognized credentials were rejected by KMS,
and not retried.

`kms:GenerateDataKeyWithoutPlaintext` and `kms:ReEncrypt`
have only been tested offline;
the author's test identity lacks those permissions on the test KMS Keys,
and the Hierarchical Keyring example fails with `AccessDeniedException`
exactly as the existing `hierarchical_keyring_example.py` does with that identity.

# Files

| File                                                                                                    | Purpose                                                       |
| ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [kms_transport.py](./kms_transport.py)                                                                  | Shared Transport                                              |
| [tenant_kms_client.py](./tenant_kms_client.py)                                                          | Tenant KMS Client                                             |
| [../multi_tenant_kms_keyring_example.py](../multi_tenant_kms_keyring_example.py)                       | AWS KMS Keyring and MRK Discovery Multi-Keyring, per Tenant   |
| [../multi_tenant_hierarchical_keyring_example.py](../multi_tenant_hierarchical_keyring_example.py)     | AWS KMS Key Store and Hierarchical Keyring, per Tenant                |
| [../legacy/multi_tenant_kms_master_key_provider.py](../legacy/multi_tenant_kms_master_key_provider.py) | MKP subclasses and example, per Tenant                        |
