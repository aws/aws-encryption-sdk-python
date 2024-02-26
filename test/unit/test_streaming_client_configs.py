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
from mock import patch

from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.defaults import ALGORITHM, FRAME_LENGTH, LINE_LENGTH
from aws_encryption_sdk.key_providers.base import MasterKeyProvider, MasterKeyProviderConfig
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.streaming_client import DecryptorConfig, EncryptorConfig, _ClientConfig

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs, build_valid_kwargs_list

pytestmark = [pytest.mark.unit, pytest.mark.local]


# Check if MPL is installed, and skip tests based on its installation status
# Ideally, this logic would be based on mocking imports and testing logic,
# but doing that introduces errors that cause other tests to fail.
try:
    from aws_cryptographic_materialproviders.mpl.references import (
        IKeyring,
    )
    HAS_MPL = True

    from aws_encryption_sdk.materials_managers.mpl.cmm import (
        CryptoMaterialsManagerFromMPL,
    )
except ImportError:
    HAS_MPL = False


class FakeCryptoMaterialsManager(CryptoMaterialsManager):
    def get_encryption_materials(self, request):
        return

    def decrypt_materials(self, request):
        return


class FakeMasterKeyProvider(MasterKeyProvider):
    _config_class = MasterKeyProviderConfig
    provider_id = "fake provider"

    def _new_master_key(self, key_id):
        return
    
if HAS_MPL:
    class FakeKeyring(IKeyring):
        def on_encrypt(self, param):
            return 
        
        def on_decrypt(self, param):
            return 


BASE_KWARGS = dict(
    source=b"",
    materials_manager=FakeCryptoMaterialsManager(),
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
)
VALID_KWARGS = {
    _ClientConfig: [
        dict(
            source=b"",
            materials_manager=FakeCryptoMaterialsManager(),
            source_length=10,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ),
        dict(
            source="",
            materials_manager=FakeCryptoMaterialsManager(),
            source_length=10,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ),
        dict(
            source=io.BytesIO(),
            materials_manager=FakeCryptoMaterialsManager(),
            source_length=10,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ),
        dict(
            source=b"",
            materials_manager=FakeCryptoMaterialsManager(),
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ),
        dict(
            source=b"",
            materials_manager=FakeCryptoMaterialsManager(),
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            max_encrypted_data_keys=3,
        ),
    ],
    EncryptorConfig: build_valid_kwargs_list(
        BASE_KWARGS, dict(encryption_context={}, algorithm=ALGORITHM, frame_length=8192)
    ),
    DecryptorConfig: build_valid_kwargs_list(BASE_KWARGS, dict(max_body_length=10)),
}
INVALID_KWARGS = {
    _ClientConfig: [
        dict(source=b"", key_provider=FakeMasterKeyProvider(), source_length=10),
        dict(
            source=b"",
            materials_manager=FakeCryptoMaterialsManager(),
            max_encrypted_data_keys=0,
        ),
    ],
    EncryptorConfig: [
        dict(source=b"", materials_manager=FakeCryptoMaterialsManager(), encryption_context=None),
        dict(source=b"", materials_manager=FakeCryptoMaterialsManager(), frame_length=None),
    ],
    DecryptorConfig: [dict(source=b"", materials_manager=FakeCryptoMaterialsManager(), max_body_length="not an int")],
}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS, INVALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


@pytest.mark.parametrize("cls", (EncryptorConfig, DecryptorConfig))
def test_parents(cls):
    assert issubclass(cls, _ClientConfig)


def test_client_config_defaults():
    test = _ClientConfig(**BASE_KWARGS)
    assert test.source_length is None
    assert test.line_length == LINE_LENGTH
    assert test.max_encrypted_data_keys is None


@pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
def test_client_config_with_mpl_attr():
    test = _ClientConfig(**BASE_KWARGS)
    assert hasattr(test, "keyring")


@pytest.mark.skipif(HAS_MPL, reason="Test should only be executed without MPL in installation")
def test_client_config_no_mpl():
    test = _ClientConfig(**BASE_KWARGS)
    assert not hasattr(test, "keyring")


def test_encryptor_config_defaults():
    test = EncryptorConfig(**BASE_KWARGS)
    assert test.encryption_context == {}
    assert test.algorithm is None
    assert test.frame_length == FRAME_LENGTH


def test_decryptor_config_defaults():
    test = DecryptorConfig(**BASE_KWARGS)
    assert test.max_body_length is None


@pytest.mark.parametrize(
    "kwargs, stream_type",
    (
        (dict(source=b"", materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
        (dict(source=b"", key_provider=FakeMasterKeyProvider()), io.BytesIO),
        (dict(source="", materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
        (dict(source=io.BytesIO(), materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
        (dict(source=six.StringIO(), materials_manager=FakeCryptoMaterialsManager()), six.StringIO),
    ),
)
def test_client_config_converts(kwargs, stream_type):
    kwargs["commitment_policy"] = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    test = _ClientConfig(**kwargs)
    assert isinstance(test.source, stream_type)
    if test.key_provider is not None:
        assert isinstance(test.materials_manager, DefaultCryptoMaterialsManager)


@pytest.mark.skipif(HAS_MPL, reason="Test should only be executed without MPL in installation")
@patch.object(_ClientConfig, "_no_mpl_attrs_post_init")
def test_GIVEN_no_mpl_WHEN_attrs_post_init_THEN_calls_no_mpl_method(
    mock_no_mpl_attrs_post_init,
):
    _ClientConfig(**BASE_KWARGS)
    mock_no_mpl_attrs_post_init.assert_called_once_with()


@pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
@patch.object(_ClientConfig, "_has_mpl_attrs_post_init")
def test_GIVEN_has_mpl_WHEN_attrs_post_init_THEN_calls_no_mpl_method(
    _has_mpl_attrs_post_init,
):
    _ClientConfig(**BASE_KWARGS)
    _has_mpl_attrs_post_init.assert_called_once_with()


@pytest.mark.skipif(not HAS_MPL, reason="Test should only be executed with MPL in installation")
@pytest.mark.parametrize(
    "kwargs, stream_type",
    (
        (dict(source=b"", materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
        (dict(source=b"", key_provider=FakeMasterKeyProvider()), io.BytesIO),
        (dict(source="", materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
        (dict(source=io.BytesIO(), materials_manager=FakeCryptoMaterialsManager()), io.BytesIO),
        (dict(source=six.StringIO(), materials_manager=FakeCryptoMaterialsManager()), six.StringIO),
        (dict(source=b"", keyring=FakeKeyring()), io.BytesIO),
    ),
)
def test_client_configs_with_mpl(
    kwargs,
    stream_type
):
    kwargs["commitment_policy"] = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT

    test = _ClientConfig(**kwargs)
    
    # In all cases, config should have a materials manager
    assert test.materials_manager is not None
    
    # If materials manager was provided, it should be directly used
    if hasattr(kwargs, "materials_manager"):
        assert kwargs["materials_manager"] == test.materials_manager

    # If MPL keyring was provided, it should be wrapped in MPL materials manager
    if hasattr(kwargs, "keyring"):
        assert test.keyring is not None
        assert test.keyring == kwargs["keyring"]
        assert isinstance(test.keyring, IKeyring)
        assert isinstance(test.materials_manager, CryptoMaterialsManagerFromMPL)

    # If native key_provider was provided, it should be wrapped in native materials manager
    if hasattr(kwargs, "key_provider"):
        assert test.key_provider is not None
        assert test.key_provider == kwargs["key_provider"]
        assert isinstance(test.materials_manager, DefaultCryptoMaterialsManager)
