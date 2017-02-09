"""
    Integration test suite for aws_encryption_sdk.kms_thick_client
"""
import io
import os
import unittest

import botocore.session
import six
from six.moves.configparser import ConfigParser

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

skip_message = 'Skipping tests due to blocking environment variable'


def skip_tests():
    blocker_var_name = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL'
    blocker_val = os.environ.get(blocker_var_name, None)
    if blocker_val != 'RUN':
        return True
    return False

VALUES = {
    'plaintext_128': six.b(
        '\xa3\xf6\xbc\x89\x95\x15(\xc8}\\\x8d=zu^{JA\xc1\xe9\xf0&m\xe6TD\x03'
        '\x165F\x85\xae\x96\xd9~ \xa6\x13\x88\xf8\xdb\xc9\x0c\xd8\xd8\xd4\xe0'
        '\x02\xe9\xdb+\xd4l\xeaq\xf6\xba.cg\xda\xe4V\xd9\x9a\x96\xe8\xf4:\xf5'
        '\xfd\xd7\xa6\xfa\xd1\x85\xa7o\xf5\x94\xbcE\x14L\xa1\x87\xd9T\xa6\x95'
        'eZVv\xfe[\xeeJ$a<9\x1f\x97\xe1\xd6\x9dQc\x8b7n\x0f\x1e\xbd\xf5\xba'
        '\x0e\xae|%\xd8L]\xa2\xa2\x08\x1f'
    ),
    'encryption_context': {
        'key_a': 'value_a',
        'key_b': 'value_b',
        'key_c': 'value_c'
    }
}


def setup_kms_master_key_provider():
    """Reads the test_values config file and builds the requested KMS Master Key Provider."""
    config = ConfigParser()
    config_file = os.sep.join([os.path.dirname(__file__), 'test_values.conf'])
    config_readme = os.sep.join([os.path.dirname(__file__), 'README'])
    if not os.path.isfile(config_file):
        raise Exception('Integration test config file missing.  See setup instructions in {}'.format(config_readme))
    config.read(config_file)
    cmk_arn = config.get('TestKMSThickClientIntegration', 'cmk_arn')
    aws_params = {}
    for key in ['aws_access_key_id', 'aws_secret_access_key', 'aws_session_token']:
        aws_params[key] = config.get('TestKMSThickClientIntegration', key)
    botocore_session = botocore.session.get_session()
    botocore_session.set_credentials(
        access_key=aws_params['aws_access_key_id'],
        secret_key=aws_params['aws_secret_access_key'],
        token=aws_params['aws_session_token']
    )
    kms_master_key_provider = KMSMasterKeyProvider(botocore_session=botocore_session)
    kms_master_key_provider.add_master_key(cmk_arn)
    return kms_master_key_provider


class TestKMSThickClientIntegration(unittest.TestCase):

    def setUp(self):
        if skip_tests():
            self.skipTest(skip_message)
        self.kms_master_key_provider = setup_kms_master_key_provider()

    def test_encryption_cycle_default_algorithm_framed_stream(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a framed message using the default algorithm.
        """
        with aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES['plaintext_128']),
            key_provider=self.kms_master_key_provider,
            mode='e',
            encryption_context=VALUES['encryption_context']
        ) as encryptor:
            ciphertext = encryptor.read()
        header_1 = encryptor.header
        with aws_encryption_sdk.stream(
            source=io.BytesIO(ciphertext),
            key_provider=self.kms_master_key_provider,
            mode='d'
        ) as decryptor:
            plaintext = decryptor.read()
        header_2 = decryptor.header
        assert plaintext == VALUES['plaintext_128']
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_framed_stream_many_lines(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a framed message with many frames using the default algorithm.
        """
        ciphertext = b''
        with aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES['plaintext_128'] * 10),
            key_provider=self.kms_master_key_provider,
            mode='e',
            encryption_context=VALUES['encryption_context'],
            frame_length=128
        ) as encryptor:
            for chunk in encryptor:
                ciphertext += chunk
        header_1 = encryptor.header
        plaintext = b''
        with aws_encryption_sdk.stream(
            source=io.BytesIO(ciphertext),
            key_provider=self.kms_master_key_provider,
            mode='d'
        ) as decryptor:
            for chunk in decryptor:
                plaintext += chunk
        header_2 = decryptor.header
        assert plaintext == VALUES['plaintext_128'] * 10
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single block message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_single_block_no_encryption_context(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single block message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_multiple_frames(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a framed message with multiple frames using the
            default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'] * 100,
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128'] * 100

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the aes_128_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single block message using the aes_128_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the aes_192_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single block message using the aes_192_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single frame message using the aes_256_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a single block message using the aes_256_gcm_iv12_tag16
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single frame message using the aes_128_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single block message using the aes_128_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single frame message using the aes_192_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha256_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single block message using the aes_192_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single frame message using the aes_256_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha256_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully for a
            single block message using the aes_256_gcm_iv12_tag16_hkdf_sha256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            frame message using the aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            block message using the aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            frame message using the aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            block message using the aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_frame(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            frame message using the aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384_single_block(self):
        """Test that the enrypt/decrypt cycle completes successfully for a single
            block message using the aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384
            algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.kms_master_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0,
            algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.kms_master_key_provider
        )
        assert plaintext == VALUES['plaintext_128']
