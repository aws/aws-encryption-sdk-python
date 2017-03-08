"""Default values for AWS Encryption SDK."""
import io

import aws_encryption_sdk.identifiers

#: Default chunk size to read data from sources in streaming clients
LINE_LENGTH = io.DEFAULT_BUFFER_SIZE

#: Standard string encoding where needed
ENCODING = 'utf-8'
#: Default frame length when using framing
FRAME_LENGTH = 4096
#: Message ID length as defined in specification
MESSAGE_ID_LENGTH = 16
#: Current specification version
VERSION = aws_encryption_sdk.identifiers.SerializationVersion.V1
#: Default message structure Type as defined in specification
TYPE = aws_encryption_sdk.identifiers.ObjectType.CUSTOMER_AE_DATA
#: Default algorithm as defined in specification
ALGORITHM = aws_encryption_sdk.identifiers.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384

#: Key to add encoded signing key to encryption context dictionary as defined in specification
ENCODED_SIGNER_KEY = 'aws-crypto-public-key'

#: Maximum number of frames allowed in one message as defined in specification
MAX_FRAME_COUNT = 4294967295  # 2 ** 32 - 1
#: Maximum bytes allowed in a single frame as defined in specification
MAX_FRAME_SIZE = 2147483647  # 2 ** 31 - 1
#: Maximum bytes allowed in a non-framed message ciphertext as defined in specification
MAX_NON_FRAMED_SIZE = 68719476704  # 2 ** 36 - 32

#: Maximum number of AAD bytes allowed as defined in specification
MAX_BYTE_ARRAY_SIZE = 65535  # 2 ** 16 - 1
