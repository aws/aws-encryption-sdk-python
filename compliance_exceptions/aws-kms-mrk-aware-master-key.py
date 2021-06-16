# Due to how Python MasterKeys and MasterKeyProviders are set up,
# there are some parts of the Java-focused spec which are non-applicable

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
# //= type=exception
# //# For each encrypted data key in the filtered set, one at a time, the
# //# master key MUST attempt to decrypt the data key.
# // Python MKs only ever attempt one EDK during one Decrypt Data Key call

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
# //= type=exception
# //# This configuration SHOULD be on initialization and SHOULD be immutable.
# // Python does not provide a good way of making fields immutable

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
# //= type=exception
# //# If this attempt results in an error, then these errors MUST be collected.
# // Python logs errors instead of collecting them.

# //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
# //= type=exception
# //# The set of encrypted data keys MUST first be filtered to match this
# //# master key's configuration.
# // Python MKs only ever deal with one EDK at a time. They are responsible
# // for determining whether they should attempt to decrypt with owns_data_key.

