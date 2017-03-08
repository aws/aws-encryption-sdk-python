"""Functional test suite for aws_encryption_sdk.kms_thick_client"""
import io
import unittest

import attr
import botocore.client
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from mock import MagicMock
import six

import aws_encryption_sdk
from aws_encryption_sdk import KMSMasterKeyProvider
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.internal.formatting.encryption_context import serialize_encryption_context
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

VALUES = {
    'data_key_256': (
        '4\xc0\x90B?\x95\x93y\xed]R\r #\xb8\x84\x98\x16\xc9\x11\xaa\xbd5\x87'
        '\xe4\xfbH\xf6\xd3\xff\xdf\xa9'
    ),
    'encrypted_data_key': six.b(
        '\n \x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xea'
        'W\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x12\xa7\x01\x01\x01\x03\x00x'
        '\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW'
        '\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00~0|\x06\t*\x86H'
        '\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01\x000h\x06\t*\x86H\x86\xf7\r'
        '\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xb9\x07'
        '\xaf\xde\x19\xb3C\xcfMFiB\x02\x01\x10\x80;\xdc\x92\x16\xb8\x9f\xf6'
        '\xe6s^\xfe\xca^\xdaP\x85\xd5\xd6PS\xda\xd8\xdc\nL\x8egX\xd84\xa1d'
        '\xa3L\xe5\x83\x9c\x1e\\\'\x80q"\xa41\xfa\xbe\xbb\x95lt\xc5\xfb\xba'
        '\xee\x07\xe0\xe4\xfa>'
    ),
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
    },
    'arn': 'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333',
    'provided': {
        'key': '\x90\x86Z\x95\x96l\'\xa7\x00yA\x9a\x1a"\xa9\x8e',
        'ciphertext': six.b(
            '\x01\x80\x00\x14\xe7\xc7\x81\xcfo\x04\xb9\xd3\xbe\xa5\xe5\t,\xb8\x8f\xeb\x00'
            '\n\x00\x01\x00\x02aa\x00\x02aa\x00\x01\x00\x07aws-kms\x00Karn:aws:kms:us-wes'
            't-2:249645522726:key/d1720f4e-953b-44bb-b9dd-fc8b9d0baa5f\x00\xbc\n \xf5\x9b'
            '\x99\x8cX\xa8U\xa9\xbbF\x00\xcf\xd2\xaf+\xd90\xfe\xf3\r\x0e\xdb\x1c\xaf\xf9'
            '\xfa\x7f\x17\xe8\xb2\xda\xc2\x12\x97\x01\x01\x01\x01\x00x\xf5\x9b\x99\x8cX'
            '\xa8U\xa9\xbbF\x00\xcf\xd2\xaf+\xd90\xfe\xf3\r\x0e\xdb\x1c\xaf\xf9\xfa\x7f'
            '\x17\xe8\xb2\xda\xc2\x00\x00\x00n0l\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0_0]'
            '\x02\x01\x000X\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04'
            '\x01.0\x11\x04\x0c\x88^o\xd5|\xf2rj`\x06\x80(\x02\x01\x10\x80+\x04\x1cb0\xaf\xff'
            'V^\x01\x94\xc2\xb1\x7fQ\x02\xde\xd6@\x875\xe9%f\x1c\xb0IS\xc7\xacx\x14\xb2\xea'
            '\xf6\x80\xfc2\xeb\x99x\xc9\x88Q\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x19m!'
            '\x15FG\xeeG\x8b\xb2\x03w\xe6\xa6\xfbm}My\x07\xef\xac*\x82\x98\xb6\x84FF\x94%\x8f'
            '\x97\xed3 \x12\x06\x16\xcf\x00\x00\x00\x00\x00\x00\x00\x1a\x82\xe2$\xb5\xbd\x8c'
            '\xb4\xcf\xdeF\xc5=$\xea\xdeJ\xe6{\xb7&\x83p9|d\xf8,\xa0\xa3\xa0 \xb3d>\x9f \x05t'
            '\xa9\x7f\x9f\xed'
        ),
        'plaintext': b"Hello, I'm Java KMS client"
    },
    'raw': {
        'sym1': {EncryptionKeyType.SYMMETRIC: b'12345678901234567890123456789012'},
        'asym1': {
            EncryptionKeyType.PRIVATE: six.b(
                '-----BEGIN RSA PRIVATE KEY-----\n'
                'MIIEowIBAAKCAQEAo8uCyhiO4JUGZV+rtNq5DBA9Lm4xkw5kTA3v6EPybs8bVXL2\n'
                'ZE6jkbo+xT4Jg/bKzUpnp1fE+T1ruGPtsPdoEmhY/P64LDNIs3sRq5U4QV9IETU1\n'
                'vIcbNNkgGhRjV8J87YNY0tV0H7tuWuZRpqnS+gjV6V9lUMkbvjMCc5IBqQc3heut\n'
                '/+fH4JwpGlGxOVXI8QAapnSy1XpCr3+PT29kydVJnIMuAoFrurojRpOQbOuVvhtA\n'
                'gARhst1Ji4nfROGYkj6eZhvkz2Bkud4/+3lGvVU5LO1vD8oY7WoGtpin3h50VcWe\n'
                'aBT4kejx4s9/G9C4R24lTH09J9HO2UUsuCqZYQIDAQABAoIBAQCfC90bCk+qaWqF\n'
                'gymC+qOWwCn4bM28gswHQb1D5r6AtKBRD8mKywVvWs7azguFVV3Fi8sspkBA2FBC\n'
                'At5p6ULoJOTL/TauzLl6djVJTCMM701WUDm2r+ZOIctXJ5bzP4n5Q4I7b0NMEL7u\n'
                'ixib4elYGr5D1vrVQAKtZHCr8gmkqyx8Mz7wkJepzBP9EeVzETCHsmiQDd5WYlO1\n'
                'C2IQYgw6MJzgM4entJ0V/GPytkodblGY95ORVK7ZhyNtda+r5BZ6/jeMW+hA3VoK\n'
                'tHSWjHt06ueVCCieZIATmYzBNt+zEz5UA2l7ksg3eWfVORJQS7a6Ef4VvbJLM9Ca\n'
                'm1kdsjelAoGBANKgvRf39i3bSuvm5VoyJuqinSb/23IH3Zo7XOZ5G164vh49E9Cq\n'
                'dOXXVxox74ppj/kbGUoOk+AvaB48zzfzNvac0a7lRHExykPH2kVrI/NwH/1OcT/x\n'
                '2e2DnFYocXcb4gbdZQ+m6X3zkxOYcONRzPVW1uMrFTWHcJveMUm4PGx7AoGBAMcU\n'
                'IRvrT6ye5se0s27gHnPweV+3xjsNtXZcK82N7duXyHmNjxrwOAv0SOhUmTkRXArM\n'
                '6aN5D8vyZBSWma2TgUKwpQYFTI+4Sp7sdkkyojGAEixJ+c5TZJNxZFrUe0FwAoic\n'
                'c2kb7ntaiEj5G+qHvykJJro5hy6uLnjiMVbAiJDTAoGAKb67241EmHAXGEwp9sdr\n'
                '2SMjnIAnQSF39UKAthkYqJxa6elXDQtLoeYdGE7/V+J2K3wIdhoPiuY6b4vD0iX9\n'
                'JcGM+WntN7YTjX2FsC588JmvbWfnoDHR7HYiPR1E58N597xXdFOzgUgORVr4PMWQ\n'
                'pqtwaZO3X2WZlvrhr+e46hMCgYBfdIdrm6jYXFjL6RkgUNZJQUTxYGzsY+ZemlNm\n'
                'fGdQo7a8kePMRuKY2MkcnXPaqTg49YgRmjq4z8CtHokRcWjJUWnPOTs8rmEZUshk\n'
                '0KJ0mbQdCFt/Uv0mtXgpFTkEZ3DPkDTGcV4oR4CRfOCl0/EU/A5VvL/U4i/mRo7h\n'
                'ye+xgQKBgD58b+9z+PR5LAJm1tZHIwb4tnyczP28PzwknxFd2qylR4ZNgvAUqGtU\n'
                'xvpUDpzMioz6zUH9YV43YNtt+5Xnzkqj+u9Mr27/H2v9XPwORGfwQ5XPwRJz/2oC\n'
                'EnPmP1SZoY9lXKUpQXHXSpDZ2rE2Klt3RHMUMHt8Zpy36E8Vwx8o\n'
                '-----END RSA PRIVATE KEY-----\n'
            ),
            EncryptionKeyType.PUBLIC: six.b(
                '-----BEGIN PUBLIC KEY-----\n'
                'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8uCyhiO4JUGZV+rtNq5\n'
                'DBA9Lm4xkw5kTA3v6EPybs8bVXL2ZE6jkbo+xT4Jg/bKzUpnp1fE+T1ruGPtsPdo\n'
                'EmhY/P64LDNIs3sRq5U4QV9IETU1vIcbNNkgGhRjV8J87YNY0tV0H7tuWuZRpqnS\n'
                '+gjV6V9lUMkbvjMCc5IBqQc3heut/+fH4JwpGlGxOVXI8QAapnSy1XpCr3+PT29k\n'
                'ydVJnIMuAoFrurojRpOQbOuVvhtAgARhst1Ji4nfROGYkj6eZhvkz2Bkud4/+3lG\n'
                'vVU5LO1vD8oY7WoGtpin3h50VcWeaBT4kejx4s9/G9C4R24lTH09J9HO2UUsuCqZ\n'
                'YQIDAQAB\n'
                '-----END PUBLIC KEY-----\n'
            )
        }
    }
}


@attr.s
class FakeRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    wrapping_algorithm = attr.ib()
    encryption_key_type = attr.ib()


class FakeRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = 'raw'
    _config_class = FakeRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        wrapping_key = VALUES['raw'][key_id][self.config.encryption_key_type]
        if key_id == 'sym1':
            wrapping_key = wrapping_key[:self.config.wrapping_algorithm.algorithm.data_key_len]
        return WrappingKey(
            wrapping_algorithm=self.config.wrapping_algorithm,
            wrapping_key=wrapping_key,
            wrapping_key_type=self.config.encryption_key_type
        )


def _mgf1_sha256_supported():
    wk = serialization.load_pem_private_key(
        data=VALUES['raw']['asym1'][EncryptionKeyType.PRIVATE],
        password=None,
        backend=default_backend()
    )
    try:
        wk.public_key().encrypt(
            plaintext=b'aosdjfoiajfoiaj;foijae;rogijaerg',
            padding=padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except cryptography.exceptions.UnsupportedAlgorithm:
        return False
    return True


class TestAwsEncryptionSdkFunctional(unittest.TestCase):

    def setUp(self):
        # Set up KMSMasterKeyProvider patch
        self.mock_kms_client = MagicMock()
        self.mock_kms_client.__class__ = botocore.client.BaseClient
        self.mock_kms_client.generate_data_key.return_value = {
            'Plaintext': six.b(''.join(VALUES['data_key_256'])),
            'CiphertextBlob': VALUES['encrypted_data_key'],
            'KeyId': VALUES['arn']
        }
        self.mock_kms_client.encrypt.return_value = {
            'CiphertextBlob': VALUES['encrypted_data_key'],
            'KeyId': VALUES['arn']
        }
        self.mock_kms_client.decrypt.return_value = {
            'Plaintext': six.b(''.join(VALUES['data_key_256'])),
            'KeyId': VALUES['arn']
        }
        self.mock_kms_key_provider = KMSMasterKeyProvider()
        self.mock_kms_key_provider._regional_clients['us-east-1'] = self.mock_kms_client
        self.mock_kms_key_provider.add_master_key(VALUES['arn'])
        self.fake_raw_key_provider_aes_gcm = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            encryption_key_type=EncryptionKeyType.SYMMETRIC
        )
        self.fake_raw_key_provider_aes_gcm.add_master_key('sym1')
        self.fake_raw_key_provider_rsa_pkcs1_private_key = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.RSA_PKCS1,
            encryption_key_type=EncryptionKeyType.PRIVATE
        )
        self.fake_raw_key_provider_rsa_pkcs1_private_key.add_master_key('asym1')
        self.fake_raw_key_provider_rsa_pkcs1_public_key = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.RSA_PKCS1,
            encryption_key_type=EncryptionKeyType.PUBLIC
        )
        self.fake_raw_key_provider_rsa_pkcs1_public_key.add_master_key('asym1')
        self.fake_raw_key_provider_rsa_oaep_sha1_private_key = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
            encryption_key_type=EncryptionKeyType.PRIVATE
        )
        self.fake_raw_key_provider_rsa_oaep_sha1_private_key.add_master_key('asym1')
        self.fake_raw_key_provider_rsa_oaep_sha1_public_key = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
            encryption_key_type=EncryptionKeyType.PUBLIC
        )
        self.fake_raw_key_provider_rsa_oaep_sha1_public_key.add_master_key('asym1')
        self.fake_raw_key_provider_rsa_oaep_sha256_private_key = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            encryption_key_type=EncryptionKeyType.PRIVATE
        )
        self.fake_raw_key_provider_rsa_oaep_sha256_private_key.add_master_key('asym1')
        self.fake_raw_key_provider_rsa_oaep_sha256_public_key = FakeRawMasterKeyProvider(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            encryption_key_type=EncryptionKeyType.PUBLIC
        )
        self.fake_raw_key_provider_rsa_oaep_sha256_public_key.add_master_key('asym1')

    def test_no_infinite_encryption_cycle_on_empty_source(self):
        """This catches a race condition where when calling encrypt with
            an empty byte string, encrypt would enter an infinite loop.
            If this test does not hang, the race condition is not present.
        """
        aws_encryption_sdk.encrypt(
            source=b'',
            key_provider=self.mock_kms_key_provider
        )

    def test_encrypt_load_header(self):
        """Test that StreamEncryptor can extract header without reading plaintext."""
        # Using a non-signed algorithm to simplify header size calculation
        algorithm = aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA256
        header_length = len(serialize_encryption_context(VALUES['encryption_context']))
        header_length += 34
        header_length += algorithm.iv_len
        header_length += algorithm.auth_len
        header_length += 6 + 7 + len(VALUES['arn']) + len(VALUES['encrypted_data_key'])
        with aws_encryption_sdk.stream(
            mode='e',
            source=VALUES['plaintext_128'],
            key_provider=self.mock_kms_key_provider,
            encryption_context=VALUES['encryption_context'],
            algorithm=algorithm,
            frame_length=1024
        ) as encryptor:
            encryptor_header = encryptor.header
        # Ensure that only the header has been written into the output buffer
        assert len(encryptor.output_buffer) == header_length
        assert encryptor_header.encryption_context == VALUES['encryption_context']

    def test_encrypt_decrypt_header_only(self):
        """Test that StreamDecryptor can extract header without reading ciphertext."""
        ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.mock_kms_key_provider,
            encryption_context=VALUES['encryption_context']
        )
        with aws_encryption_sdk.stream(
            mode='d',
            source=ciphertext,
            key_provider=self.mock_kms_key_provider
        ) as decryptor:
            decryptor_header = decryptor.header
        assert decryptor.output_buffer == b''
        assert all(
            pair in decryptor_header.encryption_context.items()
            for pair in encryptor_header.encryption_context.items()
        )

    def test_encryption_cycle_default_algorithm_non_framed(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.mock_kms_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.mock_kms_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_non_framed_fake_aes(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake AES-GCM
            key provider.
        """
        key_provider = self.fake_raw_key_provider_aes_gcm
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_non_framed_fake_rsa_pkcs(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake RSA-PKCS
            key provider.
        """
        key_provider = self.fake_raw_key_provider_rsa_pkcs1_private_key
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_non_framed_fake_rsa_pkcs_asymmetric(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake RSA-PKCS
            key provider.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.fake_raw_key_provider_rsa_pkcs1_public_key,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.fake_raw_key_provider_rsa_pkcs1_private_key
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_non_framed_fake_rsa_oaep_sha1(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake RSA-OAEP-SHA1
            key provider.
        """
        key_provider = self.fake_raw_key_provider_rsa_oaep_sha1_private_key
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_non_framed_fake_rsa_oaep_sha1_asymmetric(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake RSA-OAEP-SHA1
            key provider.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.fake_raw_key_provider_rsa_oaep_sha1_public_key,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.fake_raw_key_provider_rsa_oaep_sha1_private_key
        )
        assert plaintext == VALUES['plaintext_128']

    @unittest.skipUnless(_mgf1_sha256_supported(), 'MGF1-SHA256 not supported by this backend')
    def test_encryption_cycle_default_algorithm_non_framed_fake_rsa_oaep_sha256(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake RSA-OAEP-SHA256
            key provider.
        """
        key_provider = self.fake_raw_key_provider_rsa_oaep_sha256_private_key
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    @unittest.skipUnless(_mgf1_sha256_supported(), 'MGF1-SHA256 not supported by this backend')
    def test_encryption_cycle_default_algorithm_non_framed_fake_rsa_oaep_sha256_asymmetric(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm and the fake RSA-OAEP-SHA256
            key provider.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.fake_raw_key_provider_rsa_oaep_sha256_public_key,
            encryption_context=VALUES['encryption_context'],
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.fake_raw_key_provider_rsa_oaep_sha256_private_key
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_non_framed_no_encryption_context(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a non-framed message
            using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.mock_kms_key_provider,
            frame_length=0
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.mock_kms_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_single_frame(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a single frame message
            using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'],
            key_provider=self.mock_kms_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.mock_kms_key_provider
        )
        assert plaintext == VALUES['plaintext_128']

    def test_encryption_cycle_default_algorithm_multiple_frames(self):
        """Test that the enrypt/decrypt cycle completes
            successfully for a framed message with multiple
            frames using the default algorithm.
        """
        ciphertext, _ = aws_encryption_sdk.encrypt(
            source=VALUES['plaintext_128'] * 100,
            key_provider=self.mock_kms_key_provider,
            encryption_context=VALUES['encryption_context'],
            frame_length=1024
        )
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=ciphertext,
            key_provider=self.mock_kms_key_provider
        )
        assert plaintext == VALUES['plaintext_128'] * 100

    def test_encryption_cycle_default_algorithm_framed_stream(self):
        """Test that the enrypt/decrypt cycle completes successfully
            for a framed message using the default algorithm.
        """
        encryptor = aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES['plaintext_128']),
            key_provider=self.mock_kms_key_provider,
            mode='e',
            encryption_context=VALUES['encryption_context']
        )
        ciphertext = encryptor.read()
        encryptor.close()
        header_1 = encryptor.header
        decryptor = aws_encryption_sdk.stream(
            source=io.BytesIO(ciphertext),
            key_provider=self.mock_kms_key_provider,
            mode='d'
        )
        plaintext = decryptor.read()
        decryptor.close()
        header_2 = decryptor.header
        assert plaintext == VALUES['plaintext_128']
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_framed_stream_many_lines_readlines(self):
        """Test that the streaming enrypt/decrypt cycle completes
            successfully for a framed message with multiple
            frames using the default algorithm.
        """
        ciphertext = b''
        encryptor = aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES['plaintext_128'] * 100),
            key_provider=self.mock_kms_key_provider,
            mode='e',
            encryption_context=VALUES['encryption_context'],
            frame_length=128
        )
        for chunk in encryptor.readlines():
            ciphertext += chunk
        encryptor.close()
        header_1 = encryptor.header
        plaintext = b''
        decryptor = aws_encryption_sdk.stream(
            source=io.BytesIO(ciphertext),
            key_provider=self.mock_kms_key_provider,
            mode='d'
        )
        for chunk in decryptor.readlines():
            plaintext += chunk
        decryptor.close()
        header_2 = decryptor.header
        assert plaintext == VALUES['plaintext_128'] * 100
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_framed_stream_many_lines_iterator(self):
        """Test that the streaming enrypt/decrypt cycle completes
            successfully for a framed message with multiple
            frames using the default algorithm.
        """
        ciphertext = b''
        encryptor = aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES['plaintext_128'] * 100),
            key_provider=self.mock_kms_key_provider,
            mode='e',
            encryption_context=VALUES['encryption_context'],
            frame_length=128
        )
        for chunk in encryptor:
            ciphertext += chunk
        encryptor.close()
        header_1 = encryptor.header
        plaintext = b''
        decryptor = aws_encryption_sdk.stream(
            source=io.BytesIO(ciphertext),
            key_provider=self.mock_kms_key_provider,
            mode='d'
        )
        for chunk in decryptor:
            plaintext += chunk
        decryptor.close()
        header_2 = decryptor.header
        assert plaintext == VALUES['plaintext_128'] * 100
        assert header_1.encryption_context == header_2.encryption_context

    def test_encryption_cycle_default_algorithm_framed_stream_many_lines_with_statement(self):
        """Test that the streaming enrypt/decrypt cycle completes
            successfully using the iterator behavior.
        """
        ciphertext = b''
        with aws_encryption_sdk.stream(
            source=io.BytesIO(VALUES['plaintext_128'] * 100),
            key_provider=self.mock_kms_key_provider,
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
            key_provider=self.mock_kms_key_provider,
            mode='d'
        ) as decryptor:
            for chunk in decryptor:
                plaintext += chunk
        header_2 = decryptor.header
        assert plaintext == VALUES['plaintext_128'] * 100
        assert header_1.encryption_context == header_2.encryption_context

    def test_decrypt_legacy_provided_message(self):
        """Tests backwards compatiblity against some legacy provided ciphertext."""
        region = 'us-west-2'
        key_info = 'arn:aws:kms:us-west-2:249645522726:key/d1720f4e-953b-44bb-b9dd-fc8b9d0baa5f'
        self.mock_kms_client.decrypt.return_value = {
            'Plaintext': six.b(''.join(VALUES['provided']['key']))
        }
        self.mock_kms_key_provider._regional_clients[region] = self.mock_kms_client
        self.mock_kms_key_provider.add_master_key(key_info)
        plaintext, _ = aws_encryption_sdk.decrypt(
            source=VALUES['provided']['ciphertext'],
            key_provider=self.mock_kms_key_provider
        )
        self.assertEqual(plaintext, VALUES['provided']['plaintext'])
