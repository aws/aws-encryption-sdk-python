"""AWS Encryption SDK native data structures for defining implementation-specific characteristics."""
from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf import hkdf

from aws_encryption_sdk.exceptions import InvalidAlgorithmError

__version__ = '1.2.0'


def _kdf_input_len_check(data_key_len, kdf_type, kdf_input_len):
    """Validates that data_key_len and kdf_input_len have the correct relationship.

    :param int data_key_len: Number of bytes in key
    :param kdf_type: KDF algorithm to use
    :param kdf_type: cryptography.io KDF object
    :param int kdf_input_len: Length of input data to feed into KDF function
    """
    if kdf_type is None and data_key_len != kdf_input_len:
        raise InvalidAlgorithmError(
            'Invalid Algorithm definition: data_key_len must equal kdf_input_len for non-KDF algorithms'
        )
    elif data_key_len > kdf_input_len:
        raise InvalidAlgorithmError(
            'Invalid Algorithm definition: data_key_len must not be greater than kdf_input_len'
        )


class Algorithm(Enum):
    """IDs of cryptographic algorithms this library knows about.

    :param int algorithm_id: KMS Encryption Algorithm ID
    :param encryption_algorithm: Encryption algorithm to use
    :type encryption_algorithm: cryptography.io ciphers algorithm object
    :param encryption_mode: Encryption mode in which to operate
    :type encryption_mode: cryptography.io ciphers modes object
    :param int iv_len: Number of bytes in IV
    :param int auth_len: Number of bytes in auth data (tag)
    :param int auth_key_len: Number of bytes in auth key (not currently supported by any algorithms)
    :param int data_key_len: Number of bytes in envelope encryption data key
    :param kdf_type: KDF algorithm to use
    :param kdf_type: cryptography.io KDF object
    :param int kdf_input_len: Number of bytes of input data to feed into KDF function
    :param kdf_hash_type: Hash algorithm to use in KDF
    :type kdf_hash_type: cryptography.io hashes object
    :param signing_algorithm_info: Information needed by signing algorithm to define behavior
    :type signing_algorithm_info: may vary (currently only ECC curve object)
    """
    __rlookup__ = {}  # algorithm_id -> Algorithm

    AES_128_GCM_IV12_TAG16 = (0x0014, algorithms.AES, modes.GCM, 12, 16, 0, 16, None, 16, None, None)
    AES_192_GCM_IV12_TAG16 = (0x0046, algorithms.AES, modes.GCM, 12, 16, 0, 24, None, 24, None, None)
    AES_256_GCM_IV12_TAG16 = (0x0078, algorithms.AES, modes.GCM, 12, 16, 0, 32, None, 32, None, None)
    AES_128_GCM_IV12_TAG16_HKDF_SHA256 = (
        0x0114, algorithms.AES, modes.GCM, 12, 16, 0, 16, hkdf.HKDF, 16, hashes.SHA256, None
    )
    AES_192_GCM_IV12_TAG16_HKDF_SHA256 = (
        0x0146, algorithms.AES, modes.GCM, 12, 16, 0, 24, hkdf.HKDF, 24, hashes.SHA256, None
    )
    AES_256_GCM_IV12_TAG16_HKDF_SHA256 = (
        0x0178, algorithms.AES, modes.GCM, 12, 16, 0, 32, hkdf.HKDF, 32, hashes.SHA256, None
    )
    AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 = (
        0x0214, algorithms.AES, modes.GCM, 12, 16, 0, 16, hkdf.HKDF, 16, hashes.SHA256, ec.SECP256R1
    )
    AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = (
        0x0346, algorithms.AES, modes.GCM, 12, 16, 0, 24, hkdf.HKDF, 24, hashes.SHA384, ec.SECP384R1
    )
    AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = (
        0x0378, algorithms.AES, modes.GCM, 12, 16, 0, 32, hkdf.HKDF, 32, hashes.SHA384, ec.SECP384R1
    )

    def __init__(
        self,
        algorithm_id,
        encryption_algorithm,
        encryption_mode,
        iv_len,
        auth_len,
        auth_key_len,
        data_key_len,
        kdf_type,
        kdf_input_len,
        kdf_hash_type,
        signing_algorithm_info
    ):
        _kdf_input_len_check(
            data_key_len=data_key_len,
            kdf_type=kdf_type,
            kdf_input_len=kdf_input_len
        )
        self.algorithm_id = algorithm_id
        self.encryption_algorithm = encryption_algorithm
        self.encryption_mode = encryption_mode
        self.iv_len = iv_len
        # Auth keys are not currently supported
        self.auth_key_len = auth_key_len
        self.auth_len = self.tag_len = auth_len
        self.data_key_len = data_key_len
        self.kdf_type = kdf_type
        self.kdf_input_len = kdf_input_len
        self.kdf_hash_type = kdf_hash_type
        self.signing_algorithm_info = signing_algorithm_info
        # All algorithms in this enum are allowed for now.
        #  This might change in the future.
        self.allowed = True
        self.__rlookup__[algorithm_id] = self

    @classmethod
    def get_by_id(cls, algorithm_id):
        """Returns the correct member based on the algorithm_id value.

        :param algorithm_id: Value of algorithm_id field with which to retrieve Algorithm
        :type algorithm_id: int
        :returns: Algorithm with ID algorithm_id
        :rtype: aws_encryption_sdk.identifiers.Algorithm
        """
        return cls.__rlookup__[algorithm_id]


class EncryptionType(Enum):
    """Identifies symmetric vs asymmetric encryption.  Used to identify encryption type for WrappingAlgorithm."""
    SYMMETRIC = 0
    ASYMMETRIC = 1


class EncryptionKeyType(Enum):
    """Identifies raw encryption key type.  Used to identify key capabilities for WrappingAlgorithm."""
    SYMMETRIC = 0
    PUBLIC = 1
    PRIVATE = 2


class WrappingAlgorithm(Enum):
    """Wrapping Algorithms for use by RawMasterKey objects.

    :param algorithm: Encryption algorithm to use for encryption of data keys
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param padding_type: Padding type to use for encryption of data keys
    :type padding_type:
    :param padding_algorithm: Padding algorithm to use for encryption of data keys
    :type padding_algorithm:
    :param padding_mgf: Padding MGF to use for encryption of data keys
    :type padding_mgf:
    """

    AES_128_GCM_IV12_TAG16_NO_PADDING = (EncryptionType.SYMMETRIC, Algorithm.AES_128_GCM_IV12_TAG16, None, None, None)
    AES_192_GCM_IV12_TAG16_NO_PADDING = (EncryptionType.SYMMETRIC, Algorithm.AES_192_GCM_IV12_TAG16, None, None, None)
    AES_256_GCM_IV12_TAG16_NO_PADDING = (EncryptionType.SYMMETRIC, Algorithm.AES_256_GCM_IV12_TAG16, None, None, None)
    RSA_PKCS1 = (EncryptionType.ASYMMETRIC, rsa, padding.PKCS1v15, None, None)
    RSA_OAEP_SHA1_MGF1 = (EncryptionType.ASYMMETRIC, rsa, padding.OAEP, hashes.SHA1, padding.MGF1)
    RSA_OAEP_SHA256_MGF1 = (EncryptionType.ASYMMETRIC, rsa, padding.OAEP, hashes.SHA256, padding.MGF1)

    def __init__(self, encryption_type, algorithm, padding_type, padding_algorithm, padding_mgf):
        self.encryption_type = encryption_type
        self.algorithm = algorithm
        if padding_type == padding.OAEP:
            padding_args = {
                'mgf': padding_mgf(
                    algorithm=padding_algorithm()
                ),
                'algorithm': padding_algorithm(),
                'label': None
            }
        else:
            padding_args = {}
        if padding_type is not None:
            padding_type = padding_type(**padding_args)
        self.padding = padding_type


class ObjectType(Enum):
    """Valid Type values per the AWS Encryption SDK message format."""
    CUSTOMER_AE_DATA = 128


class SequenceIdentifier(Enum):
    """Identifiers for specific sequence frames."""
    SEQUENCE_NUMBER_END = 0xFFFFFFFF


class SerializationVersion(Enum):
    """Valid Versions of AWS Encryption SDK message format."""
    V1 = 1


class ContentType(Enum):
    """Type of content framing contained in message."""
    NO_FRAMING = 1
    FRAMED_DATA = 2


class ContentAADString(Enum):
    """Body Additional Authenticated Data values for building the AAD for a message body."""
    FRAME_STRING_ID = b'AWSKMSEncryptionClient Frame'
    FINAL_FRAME_STRING_ID = b'AWSKMSEncryptionClient Final Frame'
    NON_FRAMED_STRING_ID = b'AWSKMSEncryptionClient Single Block'
