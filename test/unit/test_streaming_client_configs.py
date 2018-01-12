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
"""Unit test suite to validate aws_encryption_sdk.streaming_client config classes."""
import io

import pytest
import six

from aws_encryption_sdk.internal.defaults import ALGORITHM, FRAME_LENGTH, LINE_LENGTH
from aws_encryption_sdk.key_providers.base import MasterKeyProvider, MasterKeyProviderConfig
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.streaming_client import _ClientConfig, DecryptorConfig, EncryptorConfig
from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs, build_valid_kwargs_list

pytestmark = [pytest.mark.unit, pytest.mark.local]


class FakeCryptoMaterialsManager(CryptoMaterialsManager):

    def get_encryption_materials(self, request):
        return

    def decrypt_materials(self, request):
        return


class FakeMasterKeyProvider(MasterKeyProvider):
    _config_class = MasterKeyProviderConfig
    provider_id = 'fake provider'

    def _new_master_key(self, key_id):
        return


BASE_KWARGS = dict(source=b'', materials_manager=FakeCryptoMaterialsManager())
VALID_KWARGS = {
    _ClientConfig: [
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), source_length=10, line_length=10),
        dict(source='', materials_manager=FakeCryptoMaterialsManager(), source_length=10, line_length=10),
        dict(source=io.BytesIO(), materials_manager=FakeCryptoMaterialsManager(), source_length=10, line_length=10),
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), source_length=10, line_length=10),
        dict(source=b'', key_provider=FakeMasterKeyProvider(), source_length=10, line_length=10),
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), line_length=10),
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), source_length=10),
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager())
    ],
    EncryptorConfig: build_valid_kwargs_list(
        BASE_KWARGS,
        dict(encryption_context={}, algorithm=ALGORITHM, frame_length=8192)
    ),
    DecryptorConfig: build_valid_kwargs_list(BASE_KWARGS, dict(max_body_length=10))
}
INVALID_KWARGS = {
    _ClientConfig: [
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), key_provider=FakeMasterKeyProvider())
    ],
    EncryptorConfig: [
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), encryption_context=None),
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), frame_length=None)
    ],
    DecryptorConfig: [
        dict(source=b'', materials_manager=FakeCryptoMaterialsManager(), max_body_length='not an int')
    ]
}


@pytest.mark.parametrize('cls, kwargs', all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize('cls, kwargs', all_invalid_kwargs(VALID_KWARGS, INVALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


@pytest.mark.parametrize('cls', (EncryptorConfig, DecryptorConfig))
def test_parents(cls):
    assert issubclass(cls, _ClientConfig)


def test_client_config_defaults():
    test = _ClientConfig(**BASE_KWARGS)
    assert test.source_length is None
    assert test.line_length == LINE_LENGTH


def test_encryptor_config_defaults():
    test = EncryptorConfig(**BASE_KWARGS)
    assert test.encryption_context == {}
    assert test.algorithm is None
    assert test.frame_length == FRAME_LENGTH


def test_decryptor_config_defautls():
    test = DecryptorConfig(**BASE_KWARGS)
    assert test.max_body_length is None


@pytest.mark.parametrize('kwargs, stream_type', (
    (dict(source=b'', materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
    (dict(source=b'', key_provider=FakeMasterKeyProvider()), io.BytesIO),
    (dict(source='', materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
    (dict(source=io.BytesIO(), materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
    (dict(source=six.StringIO(), materials_manager=FakeCryptoMaterialsManager()), six.StringIO)
))
def test_client_config_converts(kwargs, stream_type):
    test = _ClientConfig(**kwargs)
    assert isinstance(test.source, stream_type)
    if test.key_provider is not None:
        assert isinstance(test.materials_manager, DefaultCryptoMaterialsManager)
