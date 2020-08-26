# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Unit test suite for high-level functions in aws_encryption_sdk module"""
import warnings

import pytest
from mock import MagicMock, patch, sentinel

import aws_encryption_sdk
import aws_encryption_sdk.internal.defaults

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestAwsEncryptionSdk(object):
    @pytest.fixture(autouse=True)
    def apply_fixtures(self):
        # Set up StreamEncryptor patch
        self.mock_stream_encryptor_patcher = patch("aws_encryption_sdk.StreamEncryptor")
        self.mock_stream_encryptor = self.mock_stream_encryptor_patcher.start()
        self.mock_stream_encryptor_instance = MagicMock()
        self.mock_stream_encryptor_instance.read.return_value = sentinel.ciphertext
        self.mock_stream_encryptor_instance.header = sentinel.header
        self.mock_stream_encryptor.return_value = self.mock_stream_encryptor_instance
        self.mock_stream_encryptor_instance.__enter__.return_value = self.mock_stream_encryptor_instance
        # Set up StreamDecryptor patch
        self.mock_stream_decryptor_patcher = patch("aws_encryption_sdk.StreamDecryptor")
        self.mock_stream_decryptor = self.mock_stream_decryptor_patcher.start()
        self.mock_stream_decryptor_instance = MagicMock()
        self.mock_stream_decryptor_instance.read.return_value = sentinel.plaintext
        self.mock_stream_decryptor_instance.header = sentinel.header
        self.mock_stream_decryptor.return_value = self.mock_stream_decryptor_instance
        self.mock_stream_decryptor_instance.__enter__.return_value = self.mock_stream_decryptor_instance
        yield
        # Run tearDown
        self.mock_stream_encryptor_patcher.stop()
        self.mock_stream_decryptor_patcher.stop()

    def test_encrypt(self):
        test_ciphertext, test_header = aws_encryption_sdk.encrypt(a=sentinel.a, b=sentinel.b, c=sentinel.b)
        self.mock_stream_encryptor.called_once_with(a=sentinel.a, b=sentinel.b, c=sentinel.b)
        assert test_ciphertext is sentinel.ciphertext
        assert test_header is sentinel.header

    def test_decrypt(self):
        test_plaintext, test_header = aws_encryption_sdk.decrypt(a=sentinel.a, b=sentinel.b, c=sentinel.b)
        self.mock_stream_encryptor.called_once_with(a=sentinel.a, b=sentinel.b, c=sentinel.b)
        assert test_plaintext is sentinel.plaintext
        assert test_header is sentinel.header

    def test_stream_encryptor_e(self):
        test = aws_encryption_sdk.stream(mode="e", a=sentinel.a, b=sentinel.b, c=sentinel.b)
        assert test is self.mock_stream_encryptor_instance
        self.mock_stream_encryptor.assert_called_once_with(a=sentinel.a, b=sentinel.b, c=sentinel.b)

    def test_stream_encryptor_encrypt(self):
        test = aws_encryption_sdk.stream(mode="ENCRYPT", a=sentinel.a, b=sentinel.b, c=sentinel.b)
        assert test is self.mock_stream_encryptor_instance

    def test_stream_decryptor_d(self):
        test = aws_encryption_sdk.stream(mode="d", a=sentinel.a, b=sentinel.b, c=sentinel.b)
        assert test is self.mock_stream_decryptor_instance
        self.mock_stream_decryptor.assert_called_once_with(a=sentinel.a, b=sentinel.b, c=sentinel.b)

    def test_stream_decryptor_decrypt(self):
        test = aws_encryption_sdk.stream(mode="DECRYPT", a=sentinel.a, b=sentinel.b, c=sentinel.b)
        assert test is self.mock_stream_decryptor_instance

    def test_stream_unknown(self):
        with pytest.raises(ValueError) as excinfo:
            aws_encryption_sdk.stream(mode="ERROR", a=sentinel.a, b=sentinel.b, c=sentinel.b)
        excinfo.match("Unsupported mode: *")

    def test_encrypt_deprecation_warning(self):
        warnings.simplefilter("error")

        with pytest.raises(DeprecationWarning) as excinfo:
            aws_encryption_sdk.encrypt(source=sentinel.a, key_provider=sentinel.b)
        excinfo.match("This method is deprecated and will be removed in a future version")

    def test_decrypt_deprecation_warning(self):
        warnings.simplefilter("error")

        with pytest.raises(DeprecationWarning) as excinfo:
            aws_encryption_sdk.decrypt(source=sentinel.a, key_provider=sentinel.b)
        excinfo.match("This method is deprecated and will be removed in a future version")

    def test_stream_deprecation_warning(self):
        warnings.simplefilter("error")

        with pytest.raises(DeprecationWarning) as excinfo:
            aws_encryption_sdk.stream(mode="e", source=sentinel.a, key_provider=sentinel.b)
        excinfo.match("This method is deprecated and will be removed in a future version")
