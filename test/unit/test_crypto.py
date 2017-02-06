"""
    Unit test suite for aws_encryption_sdk.internal.crypto
"""
import unittest
from mock import MagicMock, patch, sentinel
import six
from aws_encryption_sdk.exceptions import NotSupportedError, InvalidDataKeyError, IncorrectMasterKeyError
import aws_encryption_sdk.internal.crypto
from aws_encryption_sdk.internal.structures import EncryptedData
from aws_encryption_sdk.internal.identifiers import EncryptionType, EncryptionKeyType
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

VALUES = {
    'iv': b'asdfzxcvqwer',
    'tag': b'asdfzxcvqwerasdf',
    'random': b'dihfoah\x23\x66',
    'encryptor': {
        'update': b'ex_update_ciphertext',
        'finalize': b'ex_finalize_ciphertext'
    },
    'decryptor': {
        'update': b'ex_update_plaintext',
        'finalize': b'ex_finalize_plaintext'
    },
    'ecc_private_key_prime': ec.EllipticCurvePrivateNumbers(
        private_value=17889917494901019016174171250566479258605401433636341402964733440624721474929058596523395852088194487740674876114796,
        public_numbers=ec.EllipticCurvePublicNumbers(
            x=9007459108199787568878509110290896090564999412935334592925575746287962476803074379865243742719141579140901207554948,
            y=1574487057865803742065434835341798147751257167933485863820054382900062216413864643113244902766112081885540347590369,
            curve=ec.SECP384R1()
        )
    ).private_key(default_backend()),
    'ecc_compressed_point': six.b(
        '\x03:\x85\xcb\xea\x11\x13\x03\x9d\x90\xf4HU\x7f\xbbj\xa1\xe1\n\xfa'
        '\x95\xd2\xe5\xa1\xaf|\x94\x98iD\x07\xd4{S\xd1\xa4o\xfa\xcdY\x03\x11'
        '\x91\x12E^\xd4;\x84'
    ),
    'ecc_private_key_char2': ec.EllipticCurvePrivateNumbers(
        private_value=131512833187976200862897177240257889476359607892474090119002870596121284569326171944650239612201181144875264734209664973820,
        public_numbers=ec.EllipticCurvePublicNumbers(
            x=783372629152728216190118671643020486604880277607267246139026062120084499867233383227220456289236528291350315438332972681898,
            y=657053766035459398820670308946963262342583342616783849689721971058264156234178067988487273332138651529574836305189297847674,
            curve=ec.SECT409K1()
        )
    ).private_key(default_backend())
}
VALUES['ciphertext'] = VALUES['encryptor']['update'] + VALUES['encryptor']['finalize']
VALUES['plaintext'] = VALUES['decryptor']['update'] + VALUES['decryptor']['finalize']


class TestCrypto(unittest.TestCase):

    def setUp(self):
        # Set up mock algorithm for tests
        self.mock_algorithm = MagicMock()
        self.mock_encryption_algorithm = MagicMock()
        self.mock_encryption_algorithm.return_value = sentinel.encryption_algorithm
        self.mock_algorithm.encryption_algorithm = self.mock_encryption_algorithm
        self.mock_encryption_mode = MagicMock()
        self.mock_encryption_mode.return_value = sentinel.encryption_mode
        self.mock_algorithm.encryption_mode = self.mock_encryption_mode
        self.mock_algorithm.iv_len = sentinel.iv_len
        self.mock_algorithm.data_key_len = sentinel.data_key_len
        self.mock_algorithm.algorithm_id = sentinel.algorithm_id
        self.mock_kdf_hash_type = MagicMock()
        self.mock_kdf_hash_type.return_value = sentinel.hash_instance
        self.mock_algorithm.kdf_hash_type = self.mock_kdf_hash_type
        self.mock_signing_algorithm_info = MagicMock()
        self.mock_signing_algorithm_info.return_value = sentinel.curve_instance
        self.mock_algorithm.signing_algorithm_info = self.mock_signing_algorithm_info
        self.mock_kdf_type_instance = MagicMock()
        self.mock_kdf_type_instance.derive.return_value = sentinel.derived_key
        self.mock_kdf_type = MagicMock()
        self.mock_kdf_type.return_value = self.mock_kdf_type_instance
        self.mock_algorithm.kdf_type = self.mock_kdf_type
        self.mock_algorithm.kdf_input_len = sentinel.kdf_input_len
        # Set up mock wrapping algorithm for tests
        self.mock_wrapping_algorithm = MagicMock()
        self.mock_wrapping_algorithm.padding = sentinel.padding
        self.mock_wrapping_algorithm.algorithm = sentinel.algorithm
        self.mock_wrapping_key = MagicMock()
        self.mock_wrapping_rsa_private_key = MagicMock()
        self.mock_wrapping_rsa_public_key = MagicMock()
        self.mock_wrapping_rsa_private_key.public_key.return_value = self.mock_wrapping_rsa_public_key
        self.mock_encrypted_data = EncryptedData(
            iv=VALUES['iv'],
            ciphertext=VALUES['ciphertext'],
            tag=VALUES['tag']
        )
        # Set up os.urandom patch
        self.mock_urandom_patcher = patch('aws_encryption_sdk.internal.crypto.os.urandom')
        self.mock_urandom = self.mock_urandom_patcher.start()
        self.mock_urandom.return_value = VALUES['random']
        # Set up cryptography backend patch
        self.mock_cryptography_backend_patcher = patch(
            'aws_encryption_sdk.internal.crypto.default_backend'
        )
        self.mock_cryptography_backend = self.mock_cryptography_backend_patcher.start()
        self.mock_cryptography_backend.return_value = sentinel.crypto_backend
        # Set up cryptography Cipher patch
        self.mock_cryptography_cipher_patcher = patch(
            'aws_encryption_sdk.internal.crypto.Cipher'
        )
        self.mock_cryptography_cipher = self.mock_cryptography_cipher_patcher.start()
        self.mock_cryptography_cipher_instance = MagicMock()
        self.mock_cryptography_cipher.return_value = self.mock_cryptography_cipher_instance
        self.mock_encryptor = MagicMock()
        self.mock_encryptor.update.return_value = VALUES['encryptor']['update']
        self.mock_encryptor.finalize.return_value = VALUES['encryptor']['finalize']
        self.mock_encryptor.tag = VALUES['tag']
        self.mock_cryptography_cipher_instance.encryptor.return_value = self.mock_encryptor
        self.mock_decryptor = MagicMock()
        self.mock_decryptor.update.return_value = VALUES['decryptor']['update']
        self.mock_decryptor.finalize.return_value = VALUES['decryptor']['finalize']
        self.mock_cryptography_cipher_instance.decryptor.return_value = self.mock_decryptor
        # Set up mock ec patch
        self.mock_cryptography_ec_patcher = patch(
            'aws_encryption_sdk.internal.crypto.ec'
        )
        self.mock_cryptography_ec = self.mock_cryptography_ec_patcher.start()
        self.mock_cryptography_ec.ECDSA.return_value = sentinel.ecdsa_instance
        self.mock_signer_private_key = MagicMock()
        self.mock_signer_private_key.signer.return_value = sentinel.signer_instance
        self.mock_cryptography_ec.generate_private_key.return_value = self.mock_signer_private_key
        self.mock_signer = MagicMock()
        self.mock_signer.finalize.return_value = sentinel.signature
        self.mock_verifier_public_key = MagicMock()
        self.mock_verifier_instance = MagicMock()
        self.mock_verifier_public_key.verifier.return_value = self.mock_verifier_instance
        # Set up mock load cryptography serialization patch
        self.mock_crypto_serialization_patcher = patch('aws_encryption_sdk.internal.crypto.serialization')
        self.mock_crypto_serialization = self.mock_crypto_serialization_patcher.start()
        self.mock_crypto_serialization.load_pem_private_key.return_value = self.mock_wrapping_rsa_private_key
        self.mock_crypto_serialization.load_pem_public_key.return_value = self.mock_wrapping_rsa_public_key

    def tearDown(self):
        self.mock_urandom_patcher.stop()
        self.mock_cryptography_backend_patcher.stop()
        self.mock_cryptography_cipher_patcher.stop()
        self.mock_cryptography_ec_patcher.stop()
        self.mock_crypto_serialization_patcher.stop()

    @patch('aws_encryption_sdk.internal.crypto._derive_data_encryption_key')
    def test_encrypt_derived_key(self, mock_derive_key):
        """Validate that the encrypt function works as
            expected with a derived key.
        """
        mock_derive_key.return_value = sentinel.derived_key
        test = aws_encryption_sdk.internal.crypto.encrypt(
            algorithm=self.mock_algorithm,
            key=sentinel.key,
            plaintext=sentinel.plaintext,
            associated_data=sentinel.aad,
            message_id=sentinel.message_id
        )
        self.mock_urandom.assert_called_with(self.mock_algorithm.iv_len)
        mock_derive_key.assert_called_with(
            source_key=sentinel.key,
            algorithm=self.mock_algorithm,
            message_id=sentinel.message_id
        )
        self.mock_cryptography_cipher.assert_called_with(
            sentinel.encryption_algorithm,
            sentinel.encryption_mode,
            backend=sentinel.crypto_backend
        )
        assert self.mock_cryptography_cipher_instance.encryptor.called
        self.mock_encryptor.authenticate_additional_data.assert_called_with(
            sentinel.aad
        )
        self.mock_encryptor.update.assert_called_with(sentinel.plaintext)
        assert self.mock_encryptor.finalize.called
        assert test == EncryptedData(
            VALUES['random'],
            VALUES['ciphertext'],
            VALUES['tag']
        )

    @patch('aws_encryption_sdk.internal.crypto._derive_data_encryption_key')
    def test_decrypt_derived_key(self, mock_derive_key):
        """Validate that the decrypt function works as
            expected with a derived key.
        """
        mock_derive_key.return_value = sentinel.derived_key
        test = aws_encryption_sdk.internal.crypto.decrypt(
            algorithm=self.mock_algorithm,
            key=sentinel.key,
            encrypted_data=EncryptedData(
                VALUES['iv'],
                VALUES['ciphertext'],
                VALUES['tag']
            ),
            associated_data=sentinel.aad,
            message_id=sentinel.message_id
        )
        mock_derive_key.assert_called_with(
            source_key=sentinel.key,
            algorithm=self.mock_algorithm,
            message_id=sentinel.message_id
        )
        self.mock_cryptography_cipher.assert_called_with(
            sentinel.encryption_algorithm,
            sentinel.encryption_mode,
            backend=sentinel.crypto_backend
        )
        assert self.mock_cryptography_cipher_instance.decryptor.called
        self.mock_decryptor.authenticate_additional_data.assert_called_with(
            sentinel.aad
        )
        self.mock_decryptor.update.assert_called_with(VALUES['ciphertext'])
        assert self.mock_decryptor.finalize.called
        assert test, VALUES['plaintext']

    @patch('aws_encryption_sdk.internal.crypto.struct.pack')
    def test_derive_data_encryption_key_with_hkdf(self, mock_pack):
        """Validate that the _derive_data_encryption_key
            function works as expected for algorithms with
            a defined HKDF hash function.
        """
        mock_pack.return_value = sentinel.packed_info
        self.mock_algorithm.kdf_hash_type.return_value = sentinel.kdf_hash_type
        test = aws_encryption_sdk.internal.crypto._derive_data_encryption_key(
            source_key=sentinel.source_key,
            algorithm=self.mock_algorithm,
            message_id=sentinel.message_id
        )
        mock_pack.assert_called_with(
            '>H16s',
            sentinel.algorithm_id,
            sentinel.message_id
        )
        self.mock_kdf_type.assert_called_with(
            algorithm=sentinel.kdf_hash_type,
            length=sentinel.data_key_len,
            salt=None,
            info=sentinel.packed_info,
            backend=sentinel.crypto_backend
        )
        self.mock_kdf_type_instance.derive.assert_called_with(
            sentinel.source_key
        )
        assert test == sentinel.derived_key

    def test_derive_data_encryption_key_no_hkdf(self):
        """Validate that the _derive_data_encryption_key
            function works as expected for algorithms with
            no defined HKDF hash function.
        """
        self.mock_algorithm.kdf_type = None
        test = aws_encryption_sdk.internal.crypto._derive_data_encryption_key(
            source_key=sentinel.source_key,
            algorithm=self.mock_algorithm,
            message_id=sentinel.message_id
        )
        assert not self.mock_kdf_type.called
        assert test == sentinel.source_key

    def test_ecc_encode_compressed_point_prime(self):
        """Validate that the _ecc_encode_compressed_point function
            works as expected for prime field curves.
        """
        compressed_point = aws_encryption_sdk.internal.crypto._ecc_encode_compressed_point(
            private_key=VALUES['ecc_private_key_prime']
        )
        assert compressed_point == VALUES['ecc_compressed_point']

    def test_ecc_encode_compressed_point_characteristic_two(self):
        """Validate that the _ecc_encode_compressed_point function
            works as expected for characteristic 2 field curves.
        """
        with six.assertRaisesRegex(self, NotSupportedError, 'Non-prime curves are not supported at this time'):
            aws_encryption_sdk.internal.crypto._ecc_encode_compressed_point(VALUES['ecc_private_key_char2'])

    def test_ecc_decode_compressed_point_prime(self):
        """Validate that the _ecc_decode_compressed_point function
            works as expected for prime field curves.
        """
        x, y = aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point(
            curve=ec.SECP384R1(),
            compressed_point=VALUES['ecc_compressed_point']
        )
        numbers = VALUES['ecc_private_key_prime'].public_key().public_numbers()
        assert x == numbers.x
        assert y == numbers.y

    @patch('aws_encryption_sdk.internal.crypto.pow')
    def test_ecc_decode_compressed_point_prime_a(self, mock_pow):
        """Validate that the _ecc_decode_compressed_point function
            works as expected for prime field curves when beta % 2 == yp.
        """
        mock_pow.return_value = 1
        _, y = aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point(
            curve=ec.SECP384R1(),
            compressed_point=VALUES['ecc_compressed_point']
        )
        assert y == 1

    @patch('aws_encryption_sdk.internal.crypto.pow')
    def test_ecc_decode_compressed_point_prime_b(self, mock_pow):
        """Validate that the _ecc_decode_compressed_point function
            works as expected for prime field curves when beta % 2 != yp.
        """
        mock_pow.return_value = 0
        _, y = aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point(
            curve=ec.SECP384R1(),
            compressed_point=VALUES['ecc_compressed_point']
        )
        assert y == aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp384r1'].p

    def test_ecc_decode_compressed_point_prime_unsupported(self):
        """Validate that the _ecc_decode_compressed_point function
            works as expected for unsupported prime field curves.
        """
        with six.assertRaisesRegex(self, NotSupportedError, 'Curve secp192r1 is not supported at this time'):
            aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point(
                curve=ec.SECP192R1(),
                compressed_point='\x02skdgaiuhgijudflkjsdgfkjsdflgjhsd'
            )

    @patch('aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS')
    def test_ecc_decode_compressed_point_prime_complex(self, mock_curve_parameters):
        """Validate that the _ecc_decode_compressed_point function
            works as expected for prime field curves with p % 4 != 3.
        """
        mock_curve_parameters.__getitem__.return_value = aws_encryption_sdk.internal.crypto._ECCCurveParameters(
            p=5,
            a=5,
            b=5
        )
        mock_curve = MagicMock()
        mock_curve.name = 'secp_mock_curve'
        with six.assertRaisesRegex(self, NotSupportedError, 'S not 1 :: Curve not supported at this time'):
            aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point(
                curve=mock_curve,
                compressed_point=VALUES['ecc_compressed_point']
            )

    def test_ecc_decode_compressed_point_characteristic_two(self):
        """Validate that the _ecc_decode_compressed_point function
            works as expected for characteristic 2 field curves.
        """
        with six.assertRaisesRegex(self, NotSupportedError, 'Non-prime curves are not supported at this time'):
            aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point(
                curve=ec.SECT409K1(),
                compressed_point='\x02skdgaiuhgijudflkjsdgfkjsdflgjhsd'
            )

    @patch('aws_encryption_sdk.internal.crypto._ecc_decode_compressed_point')
    def test_ecc_public_numbers_from_compressed_point(self, mock_decode):
        """Validate that the _ecc_public_numbers_from_compressed_point
            function works as expected.
        """
        mock_decode.return_value = sentinel.x, sentinel.y
        self.mock_cryptography_ec.EllipticCurvePublicNumbers.return_value = sentinel.public_numbers_instance
        test = aws_encryption_sdk.internal.crypto._ecc_public_numbers_from_compressed_point(
            curve=sentinel.curve_instance,
            compressed_point=sentinel.compressed_point
        )
        mock_decode.assert_called_once_with(sentinel.curve_instance, sentinel.compressed_point)
        self.mock_cryptography_ec.EllipticCurvePublicNumbers.assert_called_once_with(
            x=sentinel.x,
            y=sentinel.y,
            curve=sentinel.curve_instance
        )
        assert test == sentinel.public_numbers_instance

    @patch('aws_encryption_sdk.internal.crypto.Signer._signer')
    def test_signer_init(self, mock_signer):
        """Validate that the Signer __init__ function works
            as expected when a key is provided.
        """
        mock_signer.return_value = sentinel.signer_instance
        signer = aws_encryption_sdk.internal.crypto.Signer(
            algorithm=self.mock_algorithm,
            key=sentinel.existing_signer_key
        )
        mock_signer.assert_called_once_with()
        assert not self.mock_cryptography_ec.generate_private_key.called
        assert signer.algorithm == self.mock_algorithm
        assert signer.key == sentinel.existing_signer_key
        assert signer.signer == sentinel.signer_instance

    @patch('aws_encryption_sdk.internal.crypto.Signer._signer')
    def test_signer_init_no_key(self, mock_signer):
        """Validate that the Signer __init__ function works
            as expected when a key is provided.
        """
        mock_signer.return_value = sentinel.signer_instance
        signer = aws_encryption_sdk.internal.crypto.Signer(self.mock_algorithm)
        self.mock_cryptography_ec.generate_private_key.assert_called_once_with(
            curve=sentinel.curve_instance,
            backend=sentinel.crypto_backend
        )
        assert signer.key == self.mock_signer_private_key

    def test_signer_signer(self):
        """Validate that the Signer._signer function works as expected."""
        aws_encryption_sdk.internal.crypto.Signer(algorithm=self.mock_algorithm)
        self.mock_algorithm.kdf_hash_type.assert_called_once_with()
        self.mock_cryptography_ec.ECDSA.assert_called_once_with(sentinel.hash_instance)
        self.mock_signer_private_key.signer.assert_called_once_with(sentinel.ecdsa_instance)

    @patch('aws_encryption_sdk.internal.crypto.base64')
    @patch('aws_encryption_sdk.internal.crypto._ecc_encode_compressed_point')
    def test_signer_encoded_public_key(self, mock_encoder, mock_base64):
        """Validate that the Signer.encoded_public_key function works as expected."""
        mock_encoder.return_value = sentinel.compressed_point
        mock_base64.b64encode.return_value = sentinel.encoded_point
        signer = aws_encryption_sdk.internal.crypto.Signer(self.mock_algorithm)
        test_key = signer.encoded_public_key()
        mock_encoder.assert_called_once_with(self.mock_signer_private_key)
        mock_base64.b64encode.assert_called_once_with(sentinel.compressed_point)
        assert test_key == sentinel.encoded_point

    @patch('aws_encryption_sdk.internal.crypto.Signer._signer')
    def test_signer_update(self, mock_signer):
        """Validate that the Signer.update function works as expected."""
        mock_signer.return_value = self.mock_signer
        signer = aws_encryption_sdk.internal.crypto.Signer(self.mock_algorithm)
        signer.update(sentinel.data)
        self.mock_signer.update.assert_called_once_with(sentinel.data)

    @patch('aws_encryption_sdk.internal.crypto.Signer._signer')
    def test_signer_finalize(self, mock_signer):
        """Validate that the Signer.finalize function works as expected."""
        mock_signer.return_value = self.mock_signer
        signer = aws_encryption_sdk.internal.crypto.Signer(self.mock_algorithm)
        test_signature = signer.finalize()
        self.mock_signer.finalize.assert_called_once_with()
        assert test_signature == sentinel.signature

    @patch('aws_encryption_sdk.internal.crypto.Verifier._verifier')
    def test_verifier_init(self, mock_verifier):
        """Validate that the Verifier __init__ function works
            as expected when a signature is provided.
        """
        mock_verifier.return_value = sentinel.verifier
        verifier = aws_encryption_sdk.internal.crypto.Verifier(
            algorithm=self.mock_algorithm,
            public_key=sentinel.public_key,
            signature=sentinel.signature
        )
        mock_verifier.assert_called_once_with(sentinel.signature)
        assert verifier.algorithm == self.mock_algorithm
        assert verifier.key == sentinel.public_key
        assert verifier.verifier == sentinel.verifier

    @patch('aws_encryption_sdk.internal.crypto.Verifier._verifier')
    def test_verifier_init_no_signature(self, mock_verifier):
        """Validate that the Verifier __init__ function works
            as expected when no signature is provided.
        """
        mock_verifier.return_value = sentinel.verifier
        aws_encryption_sdk.internal.crypto.Verifier(
            algorithm=self.mock_algorithm,
            public_key=sentinel.public_key
        )
        mock_verifier.assert_called_once_with(b'')

    @patch('aws_encryption_sdk.internal.crypto.Verifier._verifier')
    @patch('aws_encryption_sdk.internal.crypto.base64')
    @patch('aws_encryption_sdk.internal.crypto._ecc_public_numbers_from_compressed_point')
    def test_verifier_from_encoded_point(self, mock_decode, mock_base64, mock_verifier):
        """Validate that the Verifier.from_encoded_point function works as expected."""
        mock_point_instance = MagicMock()
        mock_point_instance.public_key.return_value = sentinel.public_key
        mock_decode.return_value = mock_point_instance
        mock_base64.b64decode.return_value = sentinel.compressed_point
        mock_verifier.return_value = sentinel.verifier
        verifier = aws_encryption_sdk.internal.crypto.Verifier.from_encoded_point(
            algorithm=self.mock_algorithm,
            encoded_point=sentinel.encoded_point,
            signature=sentinel.signature
        )
        mock_base64.b64decode.assert_called_once_with(sentinel.encoded_point)
        self.mock_algorithm.signing_algorithm_info.assert_called_once_with()
        mock_decode.assert_called_once_with(
            curve=sentinel.curve_instance,
            compressed_point=sentinel.compressed_point
        )
        mock_point_instance.public_key.assert_called_once_with(sentinel.crypto_backend)
        assert isinstance(verifier, aws_encryption_sdk.internal.crypto.Verifier)

    def test_verifier_verifier(self):
        """Validate that the Verifier._verifier function works as expected."""
        verifier = aws_encryption_sdk.internal.crypto.Verifier(
            algorithm=self.mock_algorithm,
            public_key=self.mock_verifier_public_key,
            signature=sentinel.signature
        )
        self.mock_algorithm.kdf_hash_type.assert_called_once_with()
        self.mock_cryptography_ec.ECDSA.assert_called_once_with(sentinel.hash_instance)
        self.mock_verifier_public_key.verifier.assert_called_once_with(
            signature=sentinel.signature,
            signature_algorithm=sentinel.ecdsa_instance
        )
        assert verifier.verifier == self.mock_verifier_instance

    def test_verifier_set_signature(self):
        """Validate that the Verifier.set_signature function works as expected."""
        self.mock_verifier_instance._signature = b''
        verifier = aws_encryption_sdk.internal.crypto.Verifier(
            algorithm=self.mock_algorithm,
            public_key=self.mock_verifier_public_key
        )
        assert verifier.verifier._signature == b''
        verifier.set_signature(sentinel.signature)
        assert verifier.verifier._signature == sentinel.signature

    def test_verifier_update(self):
        """Validate that the Verifier.update function works as expected."""
        verifier = aws_encryption_sdk.internal.crypto.Verifier(
            algorithm=self.mock_algorithm,
            public_key=self.mock_verifier_public_key
        )
        verifier.update(sentinel.data)
        self.mock_verifier_instance.update.assert_called_once_with(sentinel.data)

    def test_verifier_verify(self):
        """Validate that the Verifier.verify function works as expected."""
        verifier = aws_encryption_sdk.internal.crypto.Verifier(
            algorithm=self.mock_algorithm,
            public_key=self.mock_verifier_public_key
        )
        verifier.verify()
        self.mock_verifier_instance.verify.assert_called_once_with()

    def test_ecc_curve_parameters_secp256r1(self):
        """Verify values from http://www.secg.org/sec2-v2.pdf"""
        p = pow(2, 224) * (pow(2, 32) - 1) + pow(2, 192) + pow(2, 96) - 1
        a = int((
            'FFFFFFFF' '00000001' '00000000' '00000000' '00000000' 'FFFFFFFF' 'FFFFFFFF'
            'FFFFFFFC'
        ), 16)
        b = int((
            '5AC635D8' 'AA3A93E7' 'B3EBBD55' '769886BC' '651D06B0' 'CC53B0F6' '3BCE3C3E'
            '27D2604B'
        ), 16)
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp256r1'].p == p
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp256r1'].a == a
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp256r1'].b == b

    def test_ecc_curve_parameters_secp384r1(self):
        """Verify values from http://www.secg.org/sec2-v2.pdf"""
        p = pow(2, 384) - pow(2, 128) - pow(2, 96) + pow(2, 32) - 1
        a = int((
            'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
            'FFFFFFFE' 'FFFFFFFF' '00000000' '00000000' 'FFFFFFFC'
        ), 16)
        b = int((
            'B3312FA7' 'E23EE7E4' '988E056B' 'E3F82D19' '181D9C6E' 'FE814112' '0314088F'
            '5013875A' 'C656398D' '8A2ED19D' '2A85C8ED' 'D3EC2AEF'
        ), 16)
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp384r1'].p == p
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp384r1'].a == a
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp384r1'].b == b

    def test_ecc_curve_parameters_secp521r1(self):
        """Verify values from http://www.secg.org/sec2-v2.pdf"""
        p = pow(2, 521) - 1
        a = int((
            '01FF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
            'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFF'
            'FFFFFFFF' 'FFFFFFFF' 'FFFFFFFC'
        ), 16)
        b = int((
            '0051' '953EB961' '8E1C9A1F' '929A21A0' 'B68540EE' 'A2DA725B' '99B315F3'
            'B8B48991' '8EF109E1' '56193951' 'EC7E937B' '1652C0BD' '3BB1BF07' '3573DF88'
            '3D2C34F1' 'EF451FD4' '6B503F00'
        ), 16)
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp521r1'].p == p
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp521r1'].a == a
        assert aws_encryption_sdk.internal.crypto._ECC_CURVE_PARAMETERS['secp521r1'].b == b

    def test_ecc_curve_not_in_cryptography(self):
        """If this test fails, then this pull or similar has gone through
            and this library should be updated to use the ECC curve
            parameters from cryptography.
            https://github.com/pyca/cryptography/pull/2499
        """
        assert not hasattr(ec.SECP384R1, 'a')

    def test_wrapping_key_init_private(self):
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PRIVATE
        )
        assert test_wrapping_key.wrapping_algorithm is self.mock_wrapping_algorithm
        assert test_wrapping_key.wrapping_key_type is EncryptionKeyType.PRIVATE
        self.mock_crypto_serialization.load_pem_private_key.assert_called_once_with(
            data=self.mock_wrapping_key,
            password=None,
            backend=sentinel.crypto_backend
        )
        assert not self.mock_crypto_serialization.load_pem_public_key.called
        assert test_wrapping_key._wrapping_key is self.mock_wrapping_rsa_private_key

    def test_wrapping_key_init_private_with_password(self):
        aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
            password=sentinel.password
        )
        self.mock_crypto_serialization.load_pem_private_key.assert_called_once_with(
            data=self.mock_wrapping_key,
            password=sentinel.password,
            backend=sentinel.crypto_backend
        )

    def test_wrapping_key_init_public(self):
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PUBLIC
        )
        self.mock_crypto_serialization.load_pem_public_key.assert_called_once_with(
            data=self.mock_wrapping_key,
            backend=sentinel.crypto_backend
        )
        assert not self.mock_crypto_serialization.load_pem_private_key.called
        assert test_wrapping_key._wrapping_key is self.mock_wrapping_rsa_public_key

    def test_wrapping_key_init_symmetric(self):
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC
        )
        assert not self.mock_crypto_serialization.load_pem_private_key.called
        assert not self.mock_crypto_serialization.load_pem_public_key.called
        assert test_wrapping_key._wrapping_key is self.mock_wrapping_key

    def test_wrapping_key_init_invalid_key_type(self):
        with six.assertRaisesRegex(self, InvalidDataKeyError, 'Invalid wrapping_key_type: *'):
            aws_encryption_sdk.internal.crypto.WrappingKey(
                wrapping_algorithm=self.mock_wrapping_algorithm,
                wrapping_key=self.mock_wrapping_key,
                wrapping_key_type=sentinel.key_type
            )

    @patch('aws_encryption_sdk.internal.crypto.serialize_encryption_context', return_value=sentinel.serialized_ec)
    @patch('aws_encryption_sdk.internal.crypto.encrypt', return_value=sentinel.encrypted_data)
    def test_wrapping_key_encrypt_symmetric(self, mock_encrypt, mock_serialize_ec):
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC
        )
        test = test_wrapping_key.encrypt(
            plaintext_data_key=sentinel.plaintext_data_key,
            encryption_context=sentinel.encryption_context
        )
        assert not self.mock_wrapping_rsa_private_key.public_key.called
        assert not self.mock_wrapping_rsa_public_key.encrypt.called
        mock_serialize_ec.assert_called_once_with(
            encryption_context=sentinel.encryption_context
        )
        mock_encrypt.assert_called_once_with(
            algorithm=sentinel.algorithm,
            key=self.mock_wrapping_key,
            plaintext=sentinel.plaintext_data_key,
            associated_data=sentinel.serialized_ec,
            message_id=None
        )
        assert test is sentinel.encrypted_data

    @patch('aws_encryption_sdk.internal.crypto.serialize_encryption_context', return_value=sentinel.serialized_ec)
    @patch('aws_encryption_sdk.internal.crypto.encrypt')
    def test_wrapping_key_encrypt_private(self, mock_encrypt, mock_serialize_ec):
        self.mock_wrapping_rsa_public_key.encrypt.return_value = VALUES['ciphertext']
        self.mock_wrapping_algorithm.encryption_type = EncryptionType.ASYMMETRIC
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PRIVATE
        )
        test = test_wrapping_key.encrypt(
            plaintext_data_key=sentinel.plaintext_data_key,
            encryption_context=sentinel.encryption_context
        )
        self.mock_wrapping_rsa_private_key.public_key.assert_called_once_with()
        self.mock_wrapping_rsa_public_key.encrypt.assert_called_once_with(
            plaintext=sentinel.plaintext_data_key,
            padding=sentinel.padding
        )
        assert not mock_serialize_ec.called
        assert not mock_encrypt.called
        assert test == EncryptedData(
            iv=None,
            ciphertext=VALUES['ciphertext'],
            tag=None
        )

    @patch('aws_encryption_sdk.internal.crypto.serialize_encryption_context', return_value=sentinel.serialized_ec)
    @patch('aws_encryption_sdk.internal.crypto.encrypt')
    def test_wrapping_key_encrypt_public(self, mock_encrypt, mock_serialize_ec):
        self.mock_wrapping_rsa_public_key.encrypt.return_value = VALUES['ciphertext']
        self.mock_wrapping_algorithm.encryption_type = EncryptionType.ASYMMETRIC
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PUBLIC
        )
        test = test_wrapping_key.encrypt(
            plaintext_data_key=sentinel.plaintext_data_key,
            encryption_context=sentinel.encryption_context
        )
        assert not self.mock_wrapping_rsa_private_key.public_key.called
        self.mock_wrapping_rsa_public_key.encrypt.assert_called_once_with(
            plaintext=sentinel.plaintext_data_key,
            padding=sentinel.padding
        )
        assert not mock_serialize_ec.called
        assert not mock_encrypt.called
        assert test == EncryptedData(
            iv=None,
            ciphertext=VALUES['ciphertext'],
            tag=None
        )

    @patch('aws_encryption_sdk.internal.crypto.serialize_encryption_context', return_value=sentinel.serialized_ec)
    @patch('aws_encryption_sdk.internal.crypto.decrypt', return_value=sentinel.plaintext_data)
    def test_wrapping_key_decrypt_symmetric(self, mock_decrypt, mock_serialize_ec):
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC
        )
        test = test_wrapping_key.decrypt(
            encrypted_wrapped_data_key=VALUES['ciphertext'],
            encryption_context=sentinel.encryption_context
        )
        assert not self.mock_wrapping_rsa_private_key.decrypt.called
        mock_serialize_ec.assert_called_once_with(
            encryption_context=sentinel.encryption_context
        )
        mock_decrypt.assert_called_once_with(
            algorithm=sentinel.algorithm,
            key=self.mock_wrapping_key,
            encrypted_data=VALUES['ciphertext'],
            associated_data=sentinel.serialized_ec,
            message_id=None
        )
        assert test is sentinel.plaintext_data

    @patch('aws_encryption_sdk.internal.crypto.serialize_encryption_context')
    @patch('aws_encryption_sdk.internal.crypto.decrypt')
    def test_wrapping_key_decrypt_private(self, mock_decrypt, mock_serialize_ec):
        self.mock_wrapping_rsa_private_key.decrypt.return_value = sentinel.plaintext_data
        self.mock_wrapping_algorithm.encryption_type = EncryptionType.ASYMMETRIC
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PRIVATE
        )
        test = test_wrapping_key.decrypt(
            encrypted_wrapped_data_key=self.mock_encrypted_data,
            encryption_context=sentinel.encryption_context
        )
        self.mock_wrapping_rsa_private_key.decrypt.assert_called_once_with(
            ciphertext=VALUES['ciphertext'],
            padding=sentinel.padding
        )
        assert not mock_serialize_ec.called
        assert not mock_decrypt.called
        assert test is sentinel.plaintext_data

    def test_wrapping_key_decrypt_public(self):
        self.mock_wrapping_algorithm.encryption_type = EncryptionType.ASYMMETRIC
        test_wrapping_key = aws_encryption_sdk.internal.crypto.WrappingKey(
            wrapping_algorithm=self.mock_wrapping_algorithm,
            wrapping_key=self.mock_wrapping_key,
            wrapping_key_type=EncryptionKeyType.PUBLIC
        )
        with six.assertRaisesRegex(self, IncorrectMasterKeyError, 'Public key cannot decrypt'):
            test_wrapping_key.decrypt(
                encrypted_wrapped_data_key=self.mock_encrypted_data,
                encryption_context=sentinel.encryption_context
            )
