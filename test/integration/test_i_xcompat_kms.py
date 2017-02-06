"""Integration test suite testing decryption of known good test files encrypted using KMSMasterKeyProvider."""
import os

import pytest

import aws_encryption_sdk

from .test_i_aws_encrytion_sdk_client import setup_kms_master_key_provider, skip_tests, skip_message
# Environment-specific test file locator.  May not always exist.
def _file_root():
    return '.'
try:
    from .aws_test_file_finder import file_root
except ImportError:
    file_root = _file_root


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
        _algset_dir = os.sep.join((_ciphertext_dir, alg_id))
        for text_size in os.listdir(_algset_dir):
            _size_dir = os.sep.join((_algset_dir, text_size))
            ptfile = os.sep.join((_plaintext_dir, text_size))
            for frame_length in os.listdir(_size_dir):
                _frame_length_dir = os.sep.join((_size_dir, frame_length))
                for ctfile in os.listdir(_frame_length_dir):
                    if 'kms' in ctfile.lower():
                        _test_cases.append((
                            ptfile,
                            os.sep.join((_frame_length_dir, ctfile))
                        ))
    return _test_cases


@pytest.mark.skipif(skip_tests(), reason=skip_message)
@pytest.mark.parametrize('plaintext_filename,ciphertext_filename', _generate_test_cases())
def test_decrypt_from_file(plaintext_filename, ciphertext_filename):
    """Tests decrypt from known good files."""
    with open(ciphertext_filename, 'rb') as infile:
        ciphertext = infile.read()
    with open(plaintext_filename, 'rb') as infile:
        plaintext = infile.read()
    decrypted_ciphertext, _header = aws_encryption_sdk.decrypt(
        source=ciphertext,
        key_provider=setup_kms_master_key_provider()
    )
    assert decrypted_ciphertext == plaintext
