# Due to how Python MasterKeys and MasterKeyProviders are set up,
# there are some parts of the Java-focused spec which are non-applicable

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
# //= type=exception
# //# The regional client
# //# supplier MUST be defined in discovery mode.
# // The Python implementation does not include a client supplier as a configuration option.
# // Instead a list of regions may be passed. If not passed, a default region will be used.
# // This behavior is true even of Discovery MKPs.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
# //= type=exception
# //# The function MUST only provide master keys if the input provider id
# //# equals "aws-kms".
# // Python does not take in provider ID as input to this new_master_key.
# // Each MK determines on it's own whether to process based on provider ID in owns_data_key

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
# //= type=exception
# //# An AWS KMS client
# //# MUST be obtained by calling the regional client supplier with this
# //# AWS Region.
# // Python doesn't use a client-supplier, but _client(new_key_id) will grab a client
# // based on the region in new_key_id, which is always the behavior we want.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
# //= type=exception
# //# The set of encrypted data keys MUST first be filtered to match this
# //# master key's configuration.
# // Each MK is responsible for defining whether an EDK matches it's configuration in
# // as part of _decrypt_data_key.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
# //= type=exception
# //# In strict mode, the requested AWS KMS key ARN MUST match a member of the configured key ids by using AWS
# //# KMS MRK Match for Decrypt (aws-kms-mrk-match-for-decrypt.md#implementation) otherwise this function MUST error.
# // Python isn't concerned with ensuring the configured key ids match during new_master_key, given that
# // Python doesn't filter EDKs before creating the master keys for decryption. Each MK is responsible for raising
# // an error if the EDK isn't an MRK aware match. For encryption, the keys are pre-populated based on the configured
# // keys, which again makes any check non-applicable.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
# //= type=exception
# //# On initialization the caller MUST provide:
# // Strict and discovery modes and their corresponding inputs are split
# // into two different classes. Additionally,
# // Python does not take in a regional client supplier,
# // but instead takes in a list of regions to create clients out of.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
# //= type=exception
# //# Finally if the
# //# provider info is identified as a multi-Region key (aws-kms-key-
# //# arn.md#identifying-an-aws-kms-multi-region-key) the AWS Region MUST
# //# be the region from the AWS KMS key in the configured key ids matched
# //# to the requested AWS KMS key by using AWS KMS MRK Match for Decrypt
# //# (aws-kms-mrk-match-for-decrypt.md#implementation).
# // This is not relevant due to the fact that Strict MRK Aware MKPs will create an MK for
# // each configured key ID on initialization, each with
# // a client that matches the region in the configured key ID.
# // During decryption, the region from the EDK's provider info does
# // not figure into what client region to use.
# // The MKs the MKP vends should always have a client region that matches the key ID

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
# //= type=exception
# //# If this attempt results in an error, then
# //# these errors MUST be collected.
# // Python logs errors instead of collecting them.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
# //= type=exception
# //# Additionally
# //# each provider info MUST be a valid AWS KMS ARN (aws-kms-key-arn.md#a-
# //# valid-aws-kms-arn) with a resource type of "key".
# // Python MKPs do not filter before using each MK to decrypt. Each MK is
# // Individually responsible for throwing if it shouldn't be used for decrypt.

