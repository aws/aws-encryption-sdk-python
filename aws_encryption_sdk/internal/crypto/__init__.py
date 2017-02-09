"""Primary cryptographic handling functions."""
from __future__ import division
import base64
from collections import namedtuple
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.utils
import six

from aws_encryption_sdk.exceptions import NotSupportedError, InvalidDataKeyError, IncorrectMasterKeyError
from aws_encryption_sdk.internal.formatting.encryption_context import serialize_encryption_context
from aws_encryption_sdk.identifiers import EncryptionType, EncryptionKeyType
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.internal.structures import EncryptedData
import aws_encryption_sdk.internal.utils


class Encryptor(object):
    """Abstract encryption handler.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Raw source key
    :param bytes associated_data: Associated Data to send to encryption subsystem
    :param bytes message_id: Message ID
    """

    def __init__(self, algorithm, key, associated_data, message_id):
        self.source_key = key

        # Construct an encryptor object with the given key and a randomly generated IV.
        # This is intentionally generic to leave an option for non-Cipher encryptor types in the future.
        self.iv = os.urandom(algorithm.iv_len)
        self._derived_key = _derive_data_encryption_key(
            source_key=key,
            algorithm=algorithm,
            message_id=message_id
        )
        self._encryptor = Cipher(
            algorithm.encryption_algorithm(self._derived_key),
            algorithm.encryption_mode(self.iv),
            backend=default_backend()
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        self._encryptor.authenticate_additional_data(associated_data)

    def update(self, plaintext):
        """Updates _encryptor with provided plaintext.

        :param bytes plaintext: Plaintext to encrypt
        :returns: Encrypted ciphertext
        :rtype: bytes
        """
        return self._encryptor.update(plaintext)

    def finalize(self):
        """Finalizes and closes _encryptor.

        :returns: Final encrypted ciphertext
        :rtype: bytes
        """
        return self._encryptor.finalize()

    @property
    def tag(self):
        """Returns the _encryptor tag from the encryption subsystem.

        :returns: Encryptor tag
        :rtype: bytes
        """
        return self._encryptor.tag


def encrypt(algorithm, key, plaintext, associated_data, message_id):
    """Encrypts a frame body.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Encryption key
    :param bytes plaintext: Body plaintext
    :param bytes associated_data: Body AAD Data
    :param bytes message_id: Message ID
    :returns: Deserialized object containing encrypted body
    :rtype: aws_encryption_sdk.internal.structures.EncryptedData
    """
    encryptor = Encryptor(algorithm, key, associated_data, message_id)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return EncryptedData(encryptor.iv, ciphertext, encryptor.tag)


class Decryptor(object):
    """Abstract decryption handler.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Raw source key
    :param bytes associated_data: Associated Data to send to decryption subsystem
    :param bytes message_id: Message ID
    :param bytes iv: IV value with which to initialize decryption subsystem
    :param bytes tag: Tag with which to validate ciphertext
    """

    def __init__(self, algorithm, key, associated_data, message_id, iv, tag):
        self.source_key = key

        # Construct a decryptor object with the given key and a randomly generated IV.
        # This is intentionally generic to leave an option for non-Cipher decryptor types in the future.
        self._derived_key = _derive_data_encryption_key(
            source_key=key,
            algorithm=algorithm,
            message_id=message_id
        )
        self._decryptor = Cipher(
            algorithm.encryption_algorithm(self._derived_key),
            algorithm.encryption_mode(iv, tag),
            backend=default_backend()
        ).decryptor()

        # Put associated_data back in or the tag will fail to verify when the _decryptor is finalized.
        self._decryptor.authenticate_additional_data(associated_data)

    def update(self, ciphertext):
        """Updates _decryptor with provided ciphertext.

        :param bytes ciphertext: Ciphertext to decrypt
        :returns: Decrypted plaintext
        :rtype: bytes
        """
        return self._decryptor.update(ciphertext)

    def finalize(self):
        """Finalizes and closes _decryptor.

        :returns: Final decrypted plaintext
        :rtype: bytes
        """
        return self._decryptor.finalize()


def decrypt(algorithm, key, encrypted_data, associated_data, message_id):
    """Decrypts a frame body.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Plaintext data key
    :param encrypted_data: EncryptedData containing body data
    :type encrypted_data: :class:`aws_encryption_sdk.internal.structures.EncryptedData`,
        :class:`aws_encryption_sdk.internal.structures.FrameBody`,
        or :class:`aws_encryption_sdk.internal.structures.MessageNoFrameBody`
    :param bytes associated_data: AAD string generated for body
    :type associated_data: bytes
    :param bytes message_id: Message ID
    :returns: Plaintext of body
    :rtype: bytes
    """
    decryptor = Decryptor(algorithm, key, associated_data, message_id, encrypted_data.iv, encrypted_data.tag)
    return decryptor.update(encrypted_data.ciphertext) + decryptor.finalize()


def _derive_data_encryption_key(source_key, algorithm, message_id):
    """Derives the data encryption key using the defined algorithm.

    :param bytes source_key: Raw source key
    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes message_id: Message ID
    :returns: Derived data encryption key
    :rtype: bytes
    """
    key = source_key
    if algorithm.kdf_type is not None:
        key = algorithm.kdf_type(
            algorithm=algorithm.kdf_hash_type(),
            length=algorithm.data_key_len,
            salt=None,
            info=struct.pack('>H16s', algorithm.algorithm_id, message_id),
            backend=default_backend()
        ).derive(source_key)
    return key


class Signer(object):
    """Abstract signing handler.

    :param algorithm: Algorithm on which to base signer
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param key: Pre-existing private key from which a signer can be generated.
    :type key: currently only EC Curves are supported
    """

    def __init__(self, algorithm, key=None):
        self.algorithm = algorithm
        if key is not None:
            self.key = key
        else:
            self.key = ec.generate_private_key(
                curve=algorithm.signing_algorithm_info(),
                backend=default_backend()
            )
        self.signer = self._signer()

    def _signer(self):
        """Creates the cryptographic signer object.

        :returns: Appropriate cryptographic signer object for Algorithm
        :rtype: may vary
        """
        return self.key.signer(ec.ECDSA(self.algorithm.kdf_hash_type()))

    def encoded_public_key(self):
        """Returns the encoded public key.

        .. note::
            For ECC curves, this will return the encoded compressed public point.

        :returns: Encoded public key from signer
        :rtype: bytes
        """
        return base64.b64encode(_ecc_encode_compressed_point(self.key))

    def update(self, data):
        """Updates the cryptographic signer with the supplied data.

        :param bytes data: Data to be signed
        """
        self.signer.update(data)

    def finalize(self):
        """Finalizes the signer and returns the signature.

        :returns: Calculated signer signature
        :rtype: bytes
        """
        return self.signer.finalize()


class Verifier(object):
    """Abstract signature verification handler.

    .. note::
        For ECC curves, the signature must be DER encoded as specified in RFC 3279.

    :param algorithm: Algorithm on which to base verifier
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param public_key: Appropriate public key object for algorithm
    :type public_key: may vary
    :param signature: The signature to verify (optional)
    :type signature: bytes
    """

    def __init__(self, algorithm, public_key, signature=b''):
        self.algorithm = algorithm
        self.key = public_key
        self.verifier = self._verifier(signature)

    @classmethod
    def from_encoded_point(cls, algorithm, encoded_point, signature=b''):
        """Creates a Verifier object based on the supplied algorithm and encoded compressed ECC curve point.

        :param algorithm: Algorithm on which to base verifier
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param bytes encoded_point: ECC public point compressed and encoded with _ecc_encode_compressed_point
        :param bytes signature: The signature to verify (optional)
        :returns: Instance of Verifier generated from encoded point
        :rtype: aws_encryption_sdk.internal.crypto.Verifier
        """
        return cls(
            algorithm=algorithm,
            public_key=_ecc_public_numbers_from_compressed_point(
                curve=algorithm.signing_algorithm_info(),
                compressed_point=base64.b64decode(encoded_point)
            ).public_key(default_backend()),
            signature=signature
        )

    def _verifier(self, signature=b''):
        """Creates the cryptographic verifier object.

        :param bytes signature: The signature to verify (optional)
        :returns: Cryptographic verifier object
        :rtype: may vary
        """
        return self.key.verifier(
            signature=signature,
            signature_algorithm=ec.ECDSA(self.algorithm.kdf_hash_type())
        )

    def set_signature(self, signature):
        """Sets the signature for the cryptographic verifier object.

        .. note::
            This is needed as the cryptography library requires
            setting the signature when the verifier is created.

        :param bytes signature: The signature to verify
        """
        self.verifier._signature = signature

    def update(self, data):
        """Updates the cryptographic verifier with the supplied data.

        :param bytes data: Data to verify using the signature
        """
        self.verifier.update(data)

    def verify(self):
        """Verifies the signature against the current cryptographic verifier state."""
        self.verifier.verify()


# Curve parameter values are included strictly as a temporary measure
#  until they can be rolled into the cryptography.io library.
# Expanded values from http://www.secg.org/sec2-v2.pdf
_ECCCurveParameters = namedtuple('_ECCCurveParameters', ['p', 'a', 'b'])
_ECC_CURVE_PARAMETERS = {
    'secp256r1': _ECCCurveParameters(
        p=115792089210356248762697446949407573530086143415290314195533631308867097853951,
        a=115792089210356248762697446949407573530086143415290314195533631308867097853948,
        b=41058363725152142129326129780047268409114441015993725554835256314039467401291
    ),
    'secp384r1': _ECCCurveParameters(
        p=39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
        a=39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316,
        b=27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
    ),
    'secp521r1': _ECCCurveParameters(
        p=6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
        a=6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148,
        b=1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
    )
}


def _ecc_encode_compressed_point(private_key):
    """Encodes a compressed elliptic curve point
        as described in SEC-1 v2 section 2.3.3
        http://www.secg.org/sec1-v2.pdf

    :param private_key: Private key from which to extract point data
    :type private_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    :returns: Encoded compressed elliptic curve point
    :rtype: bytes
    :raises NotSupportedError: for non-prime curves
    """
    # key_size is in bits. Convert to bytes and round up
    byte_length = (private_key.curve.key_size + 7) // 8
    public_numbers = private_key.public_key().public_numbers()
    y_map = [b'\x02', b'\x03']
    # If curve in prime field.
    if private_key.curve.name.startswith('secp'):
        yp = public_numbers.y % 2
        Y = y_map[yp]
    else:
        raise NotSupportedError('Non-prime curves are not supported at this time')
    return Y + cryptography.utils.int_to_bytes(public_numbers.x, byte_length)


def _ecc_decode_compressed_point(curve, compressed_point):
    """Decodes a compressed elliptic curve point
        as described in SEC-1 v2 section 2.3.4
        http://www.secg.org/sec1-v2.pdf

    :param curve: Elliptic curve type to generate
    :type curve: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve
    :param bytes compressed_point: Encoded compressed elliptic curve point
    :returns: X and Y coordinates from compressed point
    :rtype: tuple of longs
    :raises NotSupportedError: for non-prime curves and unsupported prime curves
    """
    yp_map = {
        b'\x02': 0,
        b'\x03': 1
    }
    X = compressed_point[1:]
    X = to_bytes(X)
    x = cryptography.utils.int_from_bytes(X, 'big')
    Y = compressed_point[0]
    # In Python3, bytes index calls return int values rather than strings
    if isinstance(Y, six.integer_types):
        Y = six.b(chr(Y))
    elif isinstance(Y, six.string_types):
        Y = six.b(Y)
    yp = yp_map[Y]
    # If curve in prime field.
    if curve.name.startswith('secp'):
        try:
            params = _ECC_CURVE_PARAMETERS[curve.name]
        except KeyError:
            raise NotSupportedError(
                'Curve {name} is not supported at this time'.format(name=curve.name)
            )
        alpha = (pow(x, 3, params.p) + (params.a * x % params.p) + params.b) % params.p
        # Only works for p % 4 == 3 at this time.
        # TODO: This is the case for all currently supported algorithms
        # This will need to be expanded if curves which do not match this are added.
        #  Python-ecdsa has these algorithms implemented.  Copy or reference?
        #  https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
        #  Handbook of Applied Cryptography, algorithms 3.34 - 3.39
        if params.p % 4 == 3:
            beta = pow(alpha, (params.p + 1) // 4, params.p)
        else:
            raise NotSupportedError('S not 1 :: Curve not supported at this time')
        if beta % 2 == yp:
            y = beta
        else:
            y = params.p - beta
    else:
        raise NotSupportedError('Non-prime curves are not supported at this time')
    return x, y


def _ecc_public_numbers_from_compressed_point(curve, compressed_point):
    """Decodes a compressed elliptic curve point
        as described in SEC-1 v2 section 2.3.3
        and returns a PublicNumbers instance
        based on the decoded point.
        http://www.secg.org/sec1-v2.pdf

    :param curve: Elliptic curve type to generate
    :type curve: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve
    :param bytes compressed_point: Encoded compressed elliptic curve point
    :returns: EllipticCurvePublicNumbers instance generated from compressed point and curve
    :rtype: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers
    """
    x, y = _ecc_decode_compressed_point(curve, compressed_point)
    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)


class WrappingKey(object):
    """Creates a wrapping encryption key object to encrypt and decrypt data keys.

    For use inside :class:`aws_encryption_sdk.key_providers.raw.RawMasterKeyProvider` objects.

    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext_data_key
    :type wrapping_algorithm: aws_encryption_sdk.identifiers.WrappingAlgorithm
    :param bytes wrapping_key: Encryption key with which to wrap plaintext_data_key
    :param wrapping_key_type: Type of encryption key with which to wrap plaintext_data_key
    :type wrapping_key_type: aws_encryption_sdk.identifiers.EncryptionKeyType
    :param str password: Password to decrypt wrapping_key (optional, currently only relevant for RSA)
    """

    def __init__(self, wrapping_algorithm, wrapping_key, wrapping_key_type, password=None):
        self.wrapping_algorithm = wrapping_algorithm
        self.wrapping_key_type = wrapping_key_type
        if wrapping_key_type is EncryptionKeyType.PRIVATE:
            self._wrapping_key = serialization.load_pem_private_key(
                data=wrapping_key,
                password=password,
                backend=default_backend()
            )
        elif wrapping_key_type is EncryptionKeyType.PUBLIC:
            self._wrapping_key = serialization.load_pem_public_key(
                data=wrapping_key,
                backend=default_backend()
            )
        elif wrapping_key_type is EncryptionKeyType.SYMMETRIC:
            self._wrapping_key = wrapping_key
        else:
            raise InvalidDataKeyError('Invalid wrapping_key_type: {}'.format(wrapping_key_type))

    def encrypt(self, plaintext_data_key, encryption_context):
        """Encrypts a data key using a direct wrapping key.

        :param bytes plaintext_data_key: Data key to encrypt
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Deserialized object containing encrypted key
        :rtype: aws_encryption_sdk.internal.structures.EncryptedData
        """
        if self.wrapping_algorithm.encryption_type is EncryptionType.ASYMMETRIC:
            if self.wrapping_key_type is EncryptionKeyType.PRIVATE:
                encrypted_key = self._wrapping_key.public_key().encrypt(
                    plaintext=plaintext_data_key,
                    padding=self.wrapping_algorithm.padding
                )
            else:
                encrypted_key = self._wrapping_key.encrypt(
                    plaintext=plaintext_data_key,
                    padding=self.wrapping_algorithm.padding
                )
            return EncryptedData(
                iv=None,
                ciphertext=encrypted_key,
                tag=None
            )
        serialized_encryption_context = serialize_encryption_context(
            encryption_context=encryption_context
        )
        return encrypt(
            algorithm=self.wrapping_algorithm.algorithm,
            key=self._wrapping_key,
            plaintext=plaintext_data_key,
            associated_data=serialized_encryption_context,
            message_id=None
        )

    def decrypt(self, encrypted_wrapped_data_key, encryption_context):
        """Decrypts a wrapped, encrypted, data key.

        :param encrypted_wrapped_data_key: Encrypted, wrapped, data key
        :type encrypted_wrapped_data_key: aws_encryption_sdk.internal.structures.EncryptedData
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Plaintext of data key
        :rtype: bytes
        """
        if self.wrapping_key_type is EncryptionKeyType.PUBLIC:
            raise IncorrectMasterKeyError('Public key cannot decrypt')
        if self.wrapping_key_type is EncryptionKeyType.PRIVATE:
            return self._wrapping_key.decrypt(
                ciphertext=encrypted_wrapped_data_key.ciphertext,
                padding=self.wrapping_algorithm.padding
            )
        serialized_encryption_context = serialize_encryption_context(
            encryption_context=encryption_context
        )
        return decrypt(
            algorithm=self.wrapping_algorithm.algorithm,
            key=self._wrapping_key,
            encrypted_data=encrypted_wrapped_data_key,
            associated_data=serialized_encryption_context,
            message_id=None
        )
