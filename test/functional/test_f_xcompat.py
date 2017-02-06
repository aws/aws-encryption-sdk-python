"""Functional test suite testing decryption of known good test files encrypted using static RawMasterKeyProvider."""
from __future__ import print_function
import binascii
import os
import struct

import attr
import pytest

import aws_encryption_sdk
from aws_encryption_sdk.internal.identifiers import WrappingAlgorithm, EncryptionKeyType
from aws_encryption_sdk.internal.str_ops import to_bytes

from .test_f_aws_encryption_sdk_client import FakeRawMasterKeyProvider, FakeRawMasterKeyProviderConfig
# Environment-specific test file locator.  May not always exist.
def _file_root():
    return '.'
try:
    from .aws_test_file_finder import file_root
except ImportError:
    file_root = _file_root


_wrapping_values = {
    'aes': {
        16: WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
        24: WrappingAlgorithm.AES_192_GCM_IV12_TAG16_NO_PADDING,
        32: WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING
    },
    'rsa': {
        'SHA-1': WrappingAlgorithm.RSA_OAEP_SHA1_MGF1
    }
}


@attr.s
class KeyData(object):
    key_name = attr.ib()
    run_name = attr.ib()
    provider_config = attr.ib()

    @classmethod
    def from_filename_and_algorithm(cls, filename, algorithm):
        run_name = filename
        if 'asym' in run_name.lower():
            key_name = 'asym1'
            key_alg = 'rsa'
            key_spec = run_name.split('-', 1)[1]
            key_type = EncryptionKeyType.PRIVATE
        else:
            key_name = 'sym1'
            key_alg = 'aes'
            key_spec = algorithm.data_key_len
            key_type = EncryptionKeyType.SYMMETRIC
        print(run_name, key_name, key_alg, key_spec, key_type)
        config = FakeRawMasterKeyProviderConfig(
            wrapping_algorithm=_wrapping_values[key_alg][key_spec],
            encryption_key_type=key_type
        )
        return KeyData(
            key_name=key_name,
            run_name=run_name,
            provider_config=config
        )


def _generate_test_cases():
    base_dir = os.sep.join((file_root(), 'aws_encryption_sdk_resources'))
    _test_cases = []
    # Files are arranged in {algorithm_id}/{text_size}/{frame_size}/{run_description}
    _ciphertext_dir = os.sep.join((base_dir, 'ciphertext'))
    _plaintext_dir = os.sep.join((base_dir, 'plaintext'))
    if not os.path.isdir(_ciphertext_dir) or not os.path.isdir(_plaintext_dir):
        raise Exception('Specified ciphertext and plaintext directories do not exist: {} {}'.format(
            _ciphertext_dir,
            _plaintext_dir
        ))
    for alg_id in os.listdir(_ciphertext_dir):
        (algorithm_id,) = struct.unpack('>H', binascii.unhexlify(to_bytes(alg_id)))
        algorithm = aws_encryption_sdk.Algorithm.get_by_id(algorithm_id)
        _algset_dir = os.sep.join((_ciphertext_dir, alg_id))
        for text_size in os.listdir(_algset_dir):
            _size_dir = os.sep.join((_algset_dir, text_size))
            ptfile = os.sep.join((_plaintext_dir, text_size))
            for frame_length in os.listdir(_size_dir):
                _frame_length_dir = os.sep.join((_size_dir, frame_length))
                for ctfile in os.listdir(_frame_length_dir):
                    if 'kms' not in ctfile.lower():
                        _test_cases.append((
                            ptfile,
                            os.sep.join((_frame_length_dir, ctfile)),
                            KeyData.from_filename_and_algorithm(ctfile, algorithm)
                        ))
    return _test_cases


@pytest.mark.parametrize('plaintext_filename,ciphertext_filename,key_case', _generate_test_cases())
def test_decrypt_from_file(plaintext_filename, ciphertext_filename, key_case):
    """Tests decrypt from known good files."""
    with open(ciphertext_filename, 'rb') as infile:
        ciphertext = infile.read()
    with open(plaintext_filename, 'rb') as infile:
        plaintext = infile.read()
    master_key_provider = FakeRawMasterKeyProvider(config=key_case.provider_config)
    master_key_provider.add_master_key(key_case.key_name)
    decrypted_ciphertext, _header = aws_encryption_sdk.decrypt(
        source=ciphertext,
        key_provider=master_key_provider
    )
    assert decrypted_ciphertext == plaintext
