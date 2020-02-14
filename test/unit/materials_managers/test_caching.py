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
"""Unit test suite for CachingCryptoMaterialsManager"""
import pytest
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.materials_managers.caching
from aws_encryption_sdk.caches.base import CryptoMaterialsCache
from aws_encryption_sdk.exceptions import CacheKeyError
from aws_encryption_sdk.internal.defaults import MAX_BYTES_PER_KEY, MAX_MESSAGES_PER_KEY
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.key_providers.base import MasterKeyProvider
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

pytestmark = [pytest.mark.unit, pytest.mark.local]


def build_ccmm(**custom_kwargs):
    kwargs = dict(
        cache=MagicMock(__class__=CryptoMaterialsCache),
        max_age=10.0,
        backing_materials_manager=MagicMock(__class__=CryptoMaterialsManager),
    )
    kwargs.update(custom_kwargs)
    return CachingCryptoMaterialsManager(**kwargs)


def fake_encryption_request():
    return MagicMock(
        encryption_context=sentinel.encryption_context,
        frame_length=sentinel.frame_length,
        algorithm=sentinel.algorithm,
        plaintext_length=sentinel.plaintext_length,
    )


@pytest.mark.parametrize(
    "invalid_kwargs",
    (
        dict(cache=None),
        dict(max_age=None),
        dict(max_messages_encrypted=None),
        dict(max_bytes_encrypted=None),
        dict(partition_name=55),
        dict(master_key_provider=None, backing_materials_manager=None),
    ),
)
def test_attrs_fail(invalid_kwargs):
    with pytest.raises(TypeError):
        build_ccmm(**invalid_kwargs)


@pytest.yield_fixture
def patch_uuid4(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.caching.uuid, "uuid4")
    yield aws_encryption_sdk.materials_managers.caching.uuid.uuid4


def test_default_values(patch_uuid4):
    mock_uuid = "this is not actually a uuid"
    patch_uuid4.return_value = mock_uuid
    test = build_ccmm()

    assert test.max_messages_encrypted == MAX_MESSAGES_PER_KEY
    assert test.max_bytes_encrypted == MAX_BYTES_PER_KEY
    assert test.partition_name == to_bytes(mock_uuid)


def test_custom_partition_name(patch_uuid4):
    mock_uuid = "this is not actually a uuid"
    patch_uuid4.return_value = mock_uuid
    custom_partition_name = b"this is a custom partition name"
    test = build_ccmm(partition_name=custom_partition_name)

    assert not patch_uuid4.called
    assert test.partition_name == custom_partition_name


def test_mkp_to_default_cmm(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.caching, "DefaultCryptoMaterialsManager")
    mock_mkp = MagicMock(__class__=MasterKeyProvider)
    test = CachingCryptoMaterialsManager(
        cache=MagicMock(__class__=CryptoMaterialsCache), max_age=10.0, master_key_provider=mock_mkp
    )

    aws_encryption_sdk.materials_managers.caching.DefaultCryptoMaterialsManager.assert_called_once_with(
        master_key_provider=mock_mkp
    )  # noqa pylint: disable=line-too-long
    assert (
        test.backing_materials_manager
        is aws_encryption_sdk.materials_managers.caching.DefaultCryptoMaterialsManager.return_value
    )  # noqa pylint: disable=line-too-long


@pytest.mark.parametrize(
    "invalid_kwargs, error_message",
    (
        (dict(max_messages_encrypted=0), r"max_messages_encrypted cannot be less than 1"),
        (
            dict(max_messages_encrypted=MAX_MESSAGES_PER_KEY + 1),
            r"max_messages_encrypted cannot exceed {}".format(MAX_MESSAGES_PER_KEY),
        ),
        (dict(max_bytes_encrypted=-1), r"max_bytes_encrypted cannot be less than 0"),
        (
            dict(max_bytes_encrypted=MAX_BYTES_PER_KEY + 1),
            r"max_bytes_encrypted cannot exceed {}".format(MAX_BYTES_PER_KEY),
        ),
        (dict(max_age=0.0), r"max_age cannot be less than or equal to 0"),
        (dict(max_age=-1.0), r"max_age cannot be less than or equal to 0"),
    ),
)
def test_invalid_values(invalid_kwargs, error_message):
    with pytest.raises(ValueError) as excinfo:
        build_ccmm(**invalid_kwargs)

    excinfo.match(error_message)


@pytest.mark.parametrize("value, result", ((-1, False), (4, False), (5, False), (6, True)))
def test_cache_entry_has_encrypted_too_many_bytes(value, result):
    entry = MagicMock(bytes_encrypted=value)
    ccmm = build_ccmm(max_bytes_encrypted=5)

    if result:
        assert ccmm._cache_entry_has_encrypted_too_many_bytes(entry)
    else:
        assert not ccmm._cache_entry_has_encrypted_too_many_bytes(entry)


@pytest.mark.parametrize("value, result", ((4, False), (5, False), (6, True)))
def test_cache_entry_has_encrypted_too_many_messages(value, result):
    entry = MagicMock(messages_encrypted=value)
    ccmm = build_ccmm(max_messages_encrypted=5)

    if result:
        assert ccmm._cache_entry_has_encrypted_too_many_messages(entry)
    else:
        assert not ccmm._cache_entry_has_encrypted_too_many_messages(entry)


@pytest.mark.parametrize("value, result", ((4, False), (5, False), (6, True)))
def test_cache_entry_is_too_old(value, result):
    entry = MagicMock(age=value)
    ccmm = build_ccmm(max_age=5.0)

    if result:
        assert ccmm._cache_entry_is_too_old(entry)
    else:
        assert not ccmm._cache_entry_is_too_old(entry)


@pytest.mark.parametrize(
    "too_old, too_many_messages, too_many_bytes, result",
    (
        (True, True, True, True),
        (True, False, False, True),
        (False, True, False, True),
        (False, False, True, True),
        (True, True, False, True),
        (False, True, True, True),
        (False, False, False, False),
    ),
)
def test_cache_entry_has_exceeded_limits(mocker, too_old, too_many_messages, too_many_bytes, result):
    mocker.patch.object(CachingCryptoMaterialsManager, "_cache_entry_is_too_old", return_value=too_old)
    mocker.patch.object(
        CachingCryptoMaterialsManager, "_cache_entry_has_encrypted_too_many_bytes", return_value=too_many_bytes
    )
    mocker.patch.object(
        CachingCryptoMaterialsManager, "_cache_entry_has_encrypted_too_many_messages", return_value=too_many_messages
    )
    ccmm = build_ccmm()

    test = ccmm._cache_entry_has_exceeded_limits(sentinel.entry)

    ccmm._cache_entry_is_too_old.assert_called_once_with(sentinel.entry)
    if too_old:
        assert not ccmm._cache_entry_has_encrypted_too_many_messages.called
    else:
        ccmm._cache_entry_has_encrypted_too_many_messages.assert_called_once_with(sentinel.entry)
        if too_many_messages:
            assert not ccmm._cache_entry_has_encrypted_too_many_bytes.called
        else:
            ccmm._cache_entry_has_encrypted_too_many_bytes.assert_called_once_with(sentinel.entry)
    if result:
        assert test
    else:
        assert not test


@pytest.yield_fixture
def patch_crypto_cache_entry_hints(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.caching, "CryptoMaterialsCacheEntryHints")
    yield aws_encryption_sdk.materials_managers.caching.CryptoMaterialsCacheEntryHints


@pytest.yield_fixture
def patch_cache_entry_has_exceeded_limits(mocker):
    mocker.patch.object(CachingCryptoMaterialsManager, "_cache_entry_has_exceeded_limits")
    yield CachingCryptoMaterialsManager._cache_entry_has_exceeded_limits


@pytest.yield_fixture
def patch_encryption_materials_request(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.caching, "EncryptionMaterialsRequest")
    yield aws_encryption_sdk.materials_managers.caching.EncryptionMaterialsRequest


@pytest.yield_fixture
def patch_build_encryption_materials_cache_key(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.caching, "build_encryption_materials_cache_key")
    yield aws_encryption_sdk.materials_managers.caching.build_encryption_materials_cache_key


@pytest.mark.parametrize(
    "plaintext_length, algorithm_provided, algorithm_safe_to_cache, response",
    ((None, False, None, False), (5, False, None, True), (5, True, False, False), (5, True, True, True)),
)
def test_should_cache_encryption_request(plaintext_length, algorithm_provided, algorithm_safe_to_cache, response):
    mock_request = MagicMock()
    mock_request.plaintext_length = plaintext_length
    if algorithm_provided:
        mock_request.algorithm.safe_to_cache.return_value = algorithm_safe_to_cache
    else:
        mock_request.algorithm = None
    ccmm = build_ccmm()

    if response:
        assert ccmm._should_cache_encryption_request(mock_request)
    else:
        assert not ccmm._should_cache_encryption_request(mock_request)


@pytest.yield_fixture
def patch_should_cache_encryption_request(mocker):
    mocker.patch.object(CachingCryptoMaterialsManager, "_should_cache_encryption_request")
    CachingCryptoMaterialsManager._should_cache_encryption_request.return_value = True
    yield CachingCryptoMaterialsManager._should_cache_encryption_request


def test_get_encryption_materials_do_not_cache(patch_should_cache_encryption_request):
    patch_should_cache_encryption_request.return_value = False
    ccmm = build_ccmm()

    test = ccmm.get_encryption_materials(sentinel.request)

    patch_should_cache_encryption_request.assert_called_once_with(sentinel.request)
    ccmm.backing_materials_manager.get_encryption_materials.assert_called_once_with(sentinel.request)
    assert test is ccmm.backing_materials_manager.get_encryption_materials.return_value


def test_get_encryption_materials_cache_hit_expired_entry(
    patch_encryption_materials_request,
    patch_should_cache_encryption_request,
    patch_cache_entry_has_exceeded_limits,
    patch_build_encryption_materials_cache_key,
    patch_crypto_cache_entry_hints,
):
    patch_cache_entry_has_exceeded_limits.return_value = True
    mock_request = fake_encryption_request()
    mock_request.plaintext_length = 10
    ccmm = build_ccmm()
    ccmm.backing_materials_manager.get_encryption_materials.return_value.algorithm.safe_to_cache.return_value = True

    test = ccmm.get_encryption_materials(mock_request)

    patch_encryption_materials_request.assert_called_once_with(
        encryption_context=sentinel.encryption_context, frame_length=sentinel.frame_length, algorithm=sentinel.algorithm
    )
    patch_build_encryption_materials_cache_key.assert_called_once_with(
        partition=ccmm.partition_name, request=patch_encryption_materials_request.return_value
    )
    ccmm.cache.get_encryption_materials.assert_called_once_with(
        cache_key=patch_build_encryption_materials_cache_key.return_value, plaintext_length=10
    )

    patch_cache_entry_has_exceeded_limits.assert_called_once_with(ccmm.cache.get_encryption_materials.return_value)
    ccmm.cache.remove.assert_called_once_with(ccmm.cache.get_encryption_materials.return_value)

    ccmm.backing_materials_manager.get_encryption_materials.assert_called_once_with(
        patch_encryption_materials_request.return_value
    )
    ccmm.backing_materials_manager.get_encryption_materials.return_value.algorithm.safe_to_cache.assert_called_once_with()  # noqa pylint: disable=line-too-long

    patch_crypto_cache_entry_hints.assert_called_once_with(lifetime=ccmm.max_age)
    ccmm.cache.put_encryption_materials.assert_called_once_with(
        cache_key=patch_build_encryption_materials_cache_key.return_value,
        encryption_materials=ccmm.backing_materials_manager.get_encryption_materials.return_value,
        plaintext_length=10,
        entry_hints=patch_crypto_cache_entry_hints.return_value,
    )

    assert test is ccmm.backing_materials_manager.get_encryption_materials.return_value


def test_get_encryption_materials_cache_hit_good_entry(
    patch_encryption_materials_request,
    patch_should_cache_encryption_request,
    patch_cache_entry_has_exceeded_limits,
    patch_build_encryption_materials_cache_key,
):
    patch_cache_entry_has_exceeded_limits.return_value = False
    mock_request = fake_encryption_request()
    ccmm = build_ccmm()

    test = ccmm.get_encryption_materials(mock_request)

    assert not ccmm.cache.remove.called
    assert not ccmm.backing_materials_manager.get_encryption_materials.called
    assert test is ccmm.cache.get_encryption_materials.return_value.value


def test_get_encryption_materials_cache_miss(
    patch_encryption_materials_request,
    patch_should_cache_encryption_request,
    patch_cache_entry_has_exceeded_limits,
    patch_build_encryption_materials_cache_key,
):
    mock_request = fake_encryption_request()
    mock_request.plaintext_length = 10
    ccmm = build_ccmm()
    ccmm.cache.get_encryption_materials.side_effect = CacheKeyError
    ccmm.backing_materials_manager.get_encryption_materials.return_value.algorithm.safe_to_cache.return_value = True

    test = ccmm.get_encryption_materials(mock_request)

    assert not patch_cache_entry_has_exceeded_limits.called
    assert not ccmm.cache.remove.called
    assert test is ccmm.backing_materials_manager.get_encryption_materials.return_value


def test_get_encryption_materials_cache_miss_plaintext_too_big_to_cache(
    patch_encryption_materials_request,
    patch_should_cache_encryption_request,
    patch_cache_entry_has_exceeded_limits,
    patch_build_encryption_materials_cache_key,
):
    mock_request = fake_encryption_request()
    mock_request.plaintext_length = 100
    ccmm = build_ccmm(max_bytes_encrypted=10)
    ccmm.cache.get_encryption_materials.side_effect = CacheKeyError
    ccmm.backing_materials_manager.get_encryption_materials.return_value.algorithm.safe_to_cache.return_value = True

    test = ccmm.get_encryption_materials(mock_request)

    assert test is ccmm.backing_materials_manager.get_encryption_materials.return_value


def test_get_encryption_materials_cache_miss_algorithm_not_safe_to_cache(
    patch_encryption_materials_request,
    patch_should_cache_encryption_request,
    patch_cache_entry_has_exceeded_limits,
    patch_build_encryption_materials_cache_key,
):
    mock_request = fake_encryption_request()
    mock_request.plaintext_length = 10
    ccmm = build_ccmm()
    ccmm.cache.get_encryption_materials.side_effect = CacheKeyError
    ccmm.backing_materials_manager.get_encryption_materials.return_value.algorithm.safe_to_cache.return_value = False

    test = ccmm.get_encryption_materials(mock_request)

    assert test is ccmm.backing_materials_manager.get_encryption_materials.return_value


@pytest.yield_fixture
def patch_build_decryption_materials_cache_key(mocker):
    mocker.patch.object(aws_encryption_sdk.materials_managers.caching, "build_decryption_materials_cache_key")
    yield aws_encryption_sdk.materials_managers.caching.build_decryption_materials_cache_key


@pytest.yield_fixture
def patch_cache_entry_is_too_old(mocker):
    mocker.patch.object(CachingCryptoMaterialsManager, "_cache_entry_is_too_old")
    return CachingCryptoMaterialsManager._cache_entry_is_too_old


def test_decrypt_materials_cache_hit_good_entry(
    patch_build_decryption_materials_cache_key, patch_cache_entry_is_too_old
):
    patch_cache_entry_is_too_old.return_value = False
    ccmm = build_ccmm()

    test = ccmm.decrypt_materials(sentinel.request)

    patch_build_decryption_materials_cache_key.assert_called_once_with(
        partition=ccmm.partition_name, request=sentinel.request
    )
    ccmm.cache.get_decryption_materials.assert_called_once_with(patch_build_decryption_materials_cache_key.return_value)
    patch_cache_entry_is_too_old.assert_called_once_with(ccmm.cache.get_decryption_materials.return_value)
    assert not ccmm.cache.remove.called
    assert not ccmm.backing_materials_manager.decrypt_materials.called
    assert not ccmm.cache.put_decryption_materials.called
    assert test is ccmm.cache.get_decryption_materials.return_value.value


def test_decrypt_materials_cache_hit_expired_entry(
    patch_build_decryption_materials_cache_key, patch_cache_entry_is_too_old
):
    patch_cache_entry_is_too_old.return_value = True
    ccmm = build_ccmm()

    test = ccmm.decrypt_materials(sentinel.request)

    ccmm.cache.remove.assert_called_once_with(ccmm.cache.get_decryption_materials.return_value)
    ccmm.backing_materials_manager.decrypt_materials.assert_called_once_with(sentinel.request)
    ccmm.cache.put_decryption_materials.assert_called_once_with(
        cache_key=patch_build_decryption_materials_cache_key.return_value,
        decryption_materials=ccmm.backing_materials_manager.decrypt_materials.return_value,
    )
    assert test is ccmm.backing_materials_manager.decrypt_materials.return_value


def test_decrypt_materials_cache_miss(patch_build_decryption_materials_cache_key, patch_cache_entry_is_too_old):
    ccmm = build_ccmm()
    ccmm.cache.get_decryption_materials.side_effect = CacheKeyError

    test = ccmm.decrypt_materials(sentinel.request)

    assert not patch_cache_entry_is_too_old.called
    assert not ccmm.cache.remove.called
    assert test is ccmm.backing_materials_manager.decrypt_materials.return_value
