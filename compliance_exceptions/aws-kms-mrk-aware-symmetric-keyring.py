# The AWS Encryption SDK - Python does not implement Keyrings

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.5
# //= type=exception
# //# MUST implement the AWS Encryption SDK Keyring interface (../keyring-
# //# interface.md#interface)

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
# //= type=exception
# //# On initialization the caller MUST provide:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
# //= type=exception
# //# The AWS KMS key identifier MUST NOT be null or empty.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
# //= type=exception
# //# The AWS KMS
# //# SDK client MUST NOT be null.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# OnEncrypt MUST take encryption materials (structures.md#encryption-
# //# materials) as input.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If the input encryption materials (structures.md#encryption-
# //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
# //# to generate a new plaintext data key by calling AWS KMS
# //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_GenerateDataKey.html).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
# //# configured AWS KMS client to make the call.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# The keyring MUST call
# //# AWS KMS GenerateDataKeys with a request constructed as follows:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If the call to AWS KMS GenerateDataKey
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_GenerateDataKey.html) does not succeed, OnEncrypt MUST NOT modify
# //# the encryption materials (structures.md#encryption-materials) and
# //# MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
# //# the response "Plaintext" length matches the specification of the
# //# algorithm suite (algorithm-suites.md)'s Key Derivation Input Length
# //# field.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# The Generate Data Key response's "KeyId" MUST be A valid AWS
# //# KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-
# //# key).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If verified, OnEncrypt MUST do the following with the response
# //# from AWS KMS GenerateDataKey
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_GenerateDataKey.html):

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# *  OnEncrypt MUST output the modified encryption materials
# //# (structures.md#encryption-materials)

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# Given a plaintext data key in the encryption materials
# //# (structures.md#encryption-materials), OnEncrypt MUST attempt to
# //# encrypt the plaintext data key using the configured AWS KMS key
# //# identifier.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# The keyring MUST call AWS KMS Encrypt
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Encrypt.html) using the configured AWS KMS client.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# The keyring
# //# MUST AWS KMS Encrypt call with a request constructed as follows:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If the call to AWS KMS Encrypt
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If the Encrypt call succeeds The response's "KeyId" MUST be A valid
# //# AWS KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-
# //# region-key).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If verified, OnEncrypt MUST do the following with the
# //# response from AWS KMS Encrypt
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Encrypt.html):

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
# //= type=exception
# //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
# //# encryption materials (structures.md#encryption-materials).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# OnDecrypt MUST take decryption materials (structures.md#decryption-
# //# materials) and a list of encrypted data keys
# //# (structures.md#encrypted-data-key) as input.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# The set of encrypted data keys MUST first be filtered to match this
# //# keyring's configuration.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# *  Its provider ID MUST exactly match the value "aws-kms".

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# *  The the function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-
# //# for-decrypt.md#implementation) called with the configured AWS KMS
# //# key identifier and the provider info MUST return "true".

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# For each encrypted data key in the filtered set, one at a time, the
# //# OnDecrypt MUST attempt to decrypt the data key.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# If this attempt
# //# results in an error, then these errors MUST be collected.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# To attempt to decrypt a particular encrypted data key
# //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
# //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Decrypt.html) with the configured AWS KMS client.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# When calling AWS KMS Decrypt
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Decrypt.html), the keyring MUST call with a request constructed
# //# as follows:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# *  The "KeyId" field in the response MUST equal the configured AWS
# //# KMS key identifier.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# *  The length of the response's "Plaintext" MUST equal the key
# //# derivation input length (algorithm-suites.md#key-derivation-input-
# //# length) specified by the algorithm suite (algorithm-suites.md)
# //# included in the input decryption materials
# //# (structures.md#decryption-materials).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# If the response does not satisfies these requirements then an error
# //# MUST be collected and the next encrypted data key in the filtered set
# //# MUST be attempted.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# If the response does satisfies these requirements then OnDecrypt MUST
# //# do the following with the response:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# If OnDecrypt fails to successfully decrypt any encrypted data key
# //# (structures.md#encrypted-data-key), then it MUST yield an error that
# //# includes all the collected errors.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# If OnDecrypt fails to successfully decrypt any encrypted data key
# //# (structures.md#encrypted-data-key), then it MUST yield an error that
# //# includes all the collected errors.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
# //= type=exception
# //# The AWS KMS
# //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
# //# valid-aws-kms-identifier).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
# //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
# //# OnDecrypt MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
# //= type=exception
# //# If the decryption materials (structures.md#decryption-materials)
# //# already contained a valid plaintext data key OnDecrypt MUST
# //# immediately return the unmodified decryption materials
# //# (structures.md#decryption-materials).

