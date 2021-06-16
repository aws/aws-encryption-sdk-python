# The AWS Encryption SDK - Python does not implement Keyrings

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# The caller MUST provide:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# If an empty set of Region is provided this function MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# If
# //# any element of the set of regions is null or an empty string this
# //# function MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# If a regional client supplier is not passed,
# //# then a default MUST be created that takes a region string and
# //# generates a default AWS SDK client for the given region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# A set of AWS KMS clients MUST be created by calling regional client
# //# supplier for each region in the input set of regions.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# Then a set of AWS KMS MRK Aware Symmetric Region Discovery Keyring
# //# (aws-kms-mrk-aware-symmetric-region-discovery-keyring.md) MUST be
# //# created for each AWS KMS client by initializing each keyring with

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
# //# by using this set of discovery keyrings as the child keyrings
# //# (../multi-keyring.md#child-keyrings).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
# //= type=exception
# //# This Multi-Keyring MUST be
# //# this functions output.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# The caller MUST provide:

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# If any of the AWS KMS key identifiers is null or an empty string this
# //# function MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# At least one non-null or non-empty string AWS
# //# KMS key identifiers exists in the input this function MUST fail.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# If
# //# a regional client supplier is not passed, then a default MUST be
# //# created that takes a region string and generates a default AWS SDK
# //# client for the given region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# If there is a generator input then the generator keyring MUST be a
# //# AWS KMS MRK Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-
# //# keyring.md) initialized with

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# *  The AWS KMS client that MUST be created by the regional client
# //# supplier when called with the region part of the generator ARN or
# //# a signal for the AWS SDK to select the default region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# If there is a set of child identifiers then a set of AWS KMS MRK
# //# Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-keyring.md) MUST
# //# be created for each AWS KMS key identifier by initialized each
# //# keyring with

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# *  The AWS KMS client that MUST be created by the regional client
# //# supplier when called with the region part of the AWS KMS key
# //# identifier or a signal for the AWS SDK to select the default
# //# region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
# //# default region.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
# //# by using this generator keyring as the generator keyring (../multi-
# //# keyring.md#generator-keyring) and this set of child keyrings as the
# //# child keyrings (../multi-keyring.md#child-keyrings).

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# This Multi-
# //# Keyring MUST be this functions output.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
# //= type=exception
# //# All
# //# AWS KMS identifiers are passed to Assert AWS KMS MRK are unique (aws-
# //# kms-mrk-are-unique.md#Implementation) and the function MUST return
# //# success otherwise this MUST fail.

