# The AWS Encryption SDK - Python does not implement Keyrings

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.5
# //= type=exception
# //# MUST implement that AWS Encryption SDK Keyring interface (../keyring-
# //# interface.md#interface)

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
# //= type=exception
# //# On initialization the caller MUST provide:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
# //= type=exception
# //# The keyring MUST know what Region the AWS KMS client is in.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
# //= type=exception
# //# It
# //# SHOULD obtain this information directly from the client as opposed to
# //# having an additional parameter.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
# //= type=exception
# //# However if it can not, then it MUST
# //# NOT create the client itself.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
# //= type=exception
# //# It SHOULD have a Region parameter and
# //# SHOULD try to identify mismatched configurations.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.7
# //= type=exception
# //# This function MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# OnDecrypt MUST take decryption materials (structures.md#decryption-
# //# materials) and a list of encrypted data keys
# //# (structures.md#encrypted-data-key) as input.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# The set of encrypted data keys MUST first be filtered to match this
# //# keyring's configuration.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  Its provider ID MUST exactly match the value "aws-kms".

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  If a discovery filter is configured, its partition and the
# //# provider info partition MUST match.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  If a discovery filter is configured, its set of accounts MUST
# //# contain the provider info account.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  If the provider info is not identified as a multi-Region key (aws-
# //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
# //# provider info's Region MUST match the AWS KMS client region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  If the provider info is not identified as a multi-Region key (aws-
# //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
# //# provider info's Region MUST match the AWS KMS client region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# For each encrypted data key in the filtered set, one at a time, the
# //# OnDecrypt MUST attempt to decrypt the data key.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# To attempt to decrypt a particular encrypted data key
# //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
# //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Decrypt.html) with the configured AWS KMS client.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# When calling AWS KMS Decrypt
# //# (https://docs.aws.amazon.com/kms/latest/APIReference/
# //# API_Decrypt.html), the keyring MUST call with a request constructed
# //# as follows:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  "KeyId": If the provider info's resource type is "key" and its
# //# resource is a multi-Region key then a new ARN MUST be created
# //# where the region part MUST equal the AWS KMS client region and
# //# every other part MUST equal the provider info.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# Otherwise it MUST
# //# be the provider info.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  The "KeyId" field in the response MUST equal the requested "KeyId"

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  The length of the response's "Plaintext" MUST equal the key
# //# derivation input length (algorithm-suites.md#key-derivation-input-
# //# length) specified by the algorithm suite (algorithm-suites.md)
# //# included in the input decryption materials
# //# (structures.md#decryption-materials).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# If the response does not satisfies these requirements then an error
# //# is collected and the next encrypted data key in the filtered set MUST
# //# be attempted.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# Since the response does satisfies these requirements then OnDecrypt
# //# MUST do the following with the response:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# If OnDecrypt fails to successfully decrypt any encrypted data key
# //# (structures.md#encrypted-data-key), then it MUST yield an error that
# //# includes all collected errors.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
# //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
# //# OnDecrypt MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
# //= type=exception
# //# If the decryption materials (structures.md#decryption-materials)
# //# already contained a valid plaintext data key OnDecrypt MUST
# //# immediately return the unmodified decryption materials
# //# (structures.md#decryption-materials).


