"""Unit test suite for aws_encryption_sdk.internal.identifiers"""
import unittest
import six
from aws_encryption_sdk.exceptions import InvalidAlgorithmError
import aws_encryption_sdk.internal.identifiers


class TestIdentifiers(unittest.TestCase):

    def test_kdf_input_len_check_valid(self):
        aws_encryption_sdk.internal.identifiers._kdf_input_len_check(
            data_key_len=5,
            kdf_type=5,
            kdf_input_len=5
        )

    def test_kdf_input_len_check_invalid_no_kdf(self):
        with six.assertRaisesRegex(
            self,
            InvalidAlgorithmError,
            'Invalid Algorithm definition: data_key_len must equal kdf_input_len for non-KDF algorithms'
        ):
            aws_encryption_sdk.internal.identifiers._kdf_input_len_check(
                data_key_len=2,
                kdf_type=None,
                kdf_input_len=5
            )

    def test_kdf_input_len_check_invalid_with_kdf(self):
        with six.assertRaisesRegex(
            self,
            InvalidAlgorithmError,
            'Invalid Algorithm definition: data_key_len must not be greater than kdf_input_len'
        ):
            aws_encryption_sdk.internal.identifiers._kdf_input_len_check(
                data_key_len=5,
                kdf_type=5,
                kdf_input_len=2
            )
