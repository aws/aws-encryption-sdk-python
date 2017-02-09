This client is a fully compliant, native Python implementation of the [AWS Encryption SDK][1].

# Getting Started
## Required Prerequisites

* Python 2.7+ or 3.x
* cryptography >= 1.4
* boto3
* attrs

## Installation

```bash
$ pip install aws-encryption-sdk
```

##Concepts
There are three main concepts that need to be understood for use of this library:

###Master Key Providers
Master Key Providers are resources which provide Master Keys.
An example of a Master Key Provider is [AWS KMS][2].

In the context of this client, a MasterKeyProvider object must contain at least one MasterKey object in order to encrypt data.

MasterKeyProvider objects can also contain other MasterKeyProviders.

###Master Keys
Master Keys provide data keys.
An example of a Master Key is a [KMS Customer Master Key][3].

###Data Keys
Data Keys are the actual encryption keys which are used to encrypt your data.

#Usage
In order to use this client, an instance of a Master Key Provider must be provided.
For the examples in this readme, the KMSMasterKeyProvider class will be used as an example.

##KMSMasterKeyProvider
The KMSMasterKeyProvider uses the [boto3 SDK][4] to interact with [AWS KMS][2], and as such requires AWS Credentials.
These can be provided either in the [standard means by which boto3 locates credentials][5], or by providing the KMSMasterKeyProvider a pre-existing instance of a botocore session.
This later option can be useful if you have some alternate means of storing your AWS credentials or
you would like to re-use an existing instance of a botocore session in order to decrease startup costs.

```python
import aws_encryption_sdk
import botocore.session

kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider()

existing_botocore_session = botocore.session.Session()
kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(botocore_session=existing_botocore_session)
```

If desired, the KMSMasterKeyProvider can be pre-loaded with one or more CMKs.
At least one CMK is required to be loaded into a KMSMasterKeyProvider in order to encrypt data.
If multiple CMKs are added, a copy of the data key encrypted by each added CMK will be included in the [final message][6].

```python
import aws_encryption_sdk

kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
])
```

CMKs from multiple regions can be added as well.

```python
import aws_encryption_sdk

kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    'arn:aws:kms:us-west-2:3333333333333:key/33333333-3333-3333-3333-333333333333',
    'arn:aws:kms:ap-northeast-1:4444444444444:key/44444444-4444-4444-4444-444444444444'
])
```


##Encryption and Decryption
Once you have an instance of a MasterKeyProvider, you can simply use one of the two high-level encrypt/decrypt functions to encrypt and decrypt your data.

```python
import aws_encryption_sdk

kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
])
my_plaintext = 'This is some super secret data!  Yup, sure is!'

my_ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
    source=my_plaintext,
    key_provider=kms_key_provider
)

decrypted_plaintext, decryptor_header = aws_encryption_sdk.decrypt(
    source=my_ciphertext,
    key_provider=kms_key_provider
)

assert my_plaintext == decrypted_plaintext
assert encryptor_header.encryption_context == decryptor_header.encryption_context
```

If desired, additional authenticating information can be provided in the form of an [encryption context][7].

```python
import aws_encryption_sdk

kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
])
my_plaintext = 'This is some super secret data!  Yup, sure is!'

my_ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
    source=my_plaintext,
    key_provider=kms_key_provider,
    encryption_context={
        'not really': 'a secret',
        'but adds': 'some authentication'
    }
)

decrypted_plaintext, decryptor_header = aws_encryption_sdk.decrypt(
    source=my_ciphertext,
    key_provider=kms_key_provider
)

assert my_plaintext == decrypted_plaintext
assert encryptor_header.encryption_context == decryptor_header.encryption_context
```

##Streaming
If you are handling large files or simply do not want to put the entire plaintext or ciphertext in memory at once, this library also provides streaming clients.
The streaming clients are file-like objects, and behave exactly as you would expect a Python file object to behave, supporting context managers and iteration.
Rather than accepting a string as input, the streaming clients expect an existing file-like object.
A simple `open()`-like entry point to the streaming clients is provided, to simplify library usage.

```python
import aws_encryption_sdk
import filecmp

kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
])
plaintext_filename = 'my-secret-data.dat'
ciphertext_filename = 'my-encrypted-data.ct'


with open(plaintext_filename, 'rb') as pt_file, open(ciphertext_filename, 'wb') as ct_file:
    with aws_encryption_sdk.stream(
        mode='e',
        source=pt_file,
        key_provider=kms_key_provider
    ) as encryptor:
        for chunk in encryptor:
            ct_file.write(chunk)

new_plaintext_filename = 'my-decrypted-data.dat'

with open(ciphertext_filename, 'rb') as ct_file, open(new_plaintext_filename, 'wb') as pt_file:
    with aws_encryption_sdk.stream(
        mode='d',
        source=ct_file,
        key_provider=kms_key_provider
    ) as decryptor:
        for chunk in decryptor:
            pt_file.write(chunk)

assert filecmp.cmp(plaintext_filename, new_plaintext_filename)
assert encryptor.header.encryption_context == decryptor.header.encryption_context
```

##Performance Considerations
Two things will significantly improve the performance of encrypt/decrypt operations with this library:

1. The line length (chunk size) (default: 8192 bytes).
2. The frame size on framed messages (default: 4096 bytes).

Each line read and each frame in a framed message involve a significant amount of overhead.  If you are encrypting
a large file, increasing the frame size and line length can offer potentially huge performance gains.  It is
recommended to tune these values to your use-case in order to obtain peak performance.


```
Tested on an m3.xlarge EC2 instance, encrypting a randomly generated 1GB test file from local disk and redirecting output to /dev/null
Encrypt:
4096 byte frame, 8192 byte line: 1m58.305s
10240 byte frame, 8192 byte line: 53.143s
4096 byte frame, 10240 byte line: 1m53.761s
10240 byte frame, 10240 byte line: 52.905s
102400 byte frame, 102400 byte line: 10.170s
single block body, 8192 byte line: 11.408s
single block body, 10240 byte line: 10.201s
single block body, 102400 byte line: 5.744s
```


[1]: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
[2]: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
[3]: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys
[4]: https://boto3.readthedocs.io/en/latest/
[5]: https://boto3.readthedocs.io/en/latest/guide/configuration.html
[6]: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
[7]: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
