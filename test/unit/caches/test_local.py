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
"""Unit testing suite for LocalCryptoMaterialsCache"""
import weakref
from collections import OrderedDict, deque

import pytest
from mock import MagicMock, call, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.caches.local
from aws_encryption_sdk.caches.local import _OPPORTUNISTIC_EVICTION_ROUNDS, LocalCryptoMaterialsCache
from aws_encryption_sdk.exceptions import CacheKeyError, NotSupportedError

pytestmark = [pytest.mark.unit, pytest.mark.local]


def build_lcmc(**custom_kwargs):
    kwargs = dict(capacity=10)
    kwargs.update(custom_kwargs)
    return LocalCryptoMaterialsCache(**kwargs)


def test_opportunistic_eviction_rounds():
    assert _OPPORTUNISTIC_EVICTION_ROUNDS == 10


@pytest.mark.parametrize("invalid_kwargs", (dict(capacity=None),))
def test_attrs_fail(invalid_kwargs):
    with pytest.raises(TypeError):
        build_lcmc(**invalid_kwargs)


@pytest.mark.parametrize(
    "invalid_kwargs, error_message", ((dict(capacity=0), r"LocalCryptoMaterialsCache capacity cannot be less than 1"),)
)
def test_invalid_values(invalid_kwargs, error_message):
    with pytest.raises(ValueError) as excinfo:
        build_lcmc(**invalid_kwargs)

    excinfo.match(error_message)


def test_defaults():
    test = build_lcmc()

    assert test._cache == OrderedDict()
    assert test._lre_deque == deque()
    assert test._init_completed


def test_setattr():
    test = build_lcmc()

    with pytest.raises(NotSupportedError) as excinfo:
        test.capacity = 0

    excinfo.match(r"capacity may not be modified on LocalCryptoMaterialsCache instances")


def test_try_to_evict_one_entry_lre_empty():
    cache = build_lcmc()
    cache._lre_deque = MagicMock(pop=MagicMock(side_effect=IndexError))

    cache._try_to_evict_one_entry()

    cache._lre_deque.pop.assert_called_once_with()
    assert not cache._lre_deque.appendleft.called


def test_try_to_evict_one_entry_dead_reference():
    cache = build_lcmc()
    mock_reference = MagicMock(return_value=None)
    cache._lre_deque = MagicMock(pop=MagicMock(return_value=mock_reference))

    cache._try_to_evict_one_entry()

    mock_reference.assert_called_once_with()
    assert not cache._lre_deque.appendleft.called


def test_try_to_evict_one_entry_entry_invalid():
    cache = build_lcmc()
    mock_entry = MagicMock(cache_key=sentinel.cache_key, valid=False)
    cache._cache[sentinel.cache_key] = sentinel.entry
    mock_reference = MagicMock(return_value=mock_entry)
    cache._lre_deque = MagicMock(pop=MagicMock(return_value=mock_reference))

    assert sentinel.cache_key in cache._cache
    cache._try_to_evict_one_entry()

    assert sentinel.cache_key not in cache._cache
    assert not cache._lre_deque.appendleft.called


def test_try_to_evict_one_entry_entry_too_old():
    cache = build_lcmc()
    mock_entry = MagicMock(cache_key=sentinel.cache_key, valid=True, is_too_old=MagicMock(return_value=True))
    cache._cache[sentinel.cache_key] = mock_entry
    mock_reference = MagicMock(return_value=mock_entry)
    cache._lre_deque = MagicMock(pop=MagicMock(return_value=mock_reference))

    assert sentinel.cache_key in cache._cache
    cache._try_to_evict_one_entry()

    assert sentinel.cache_key not in cache._cache
    mock_entry.invalidate.assert_called_once_with()
    assert not cache._lre_deque.appendleft.called


def test_try_to_evict_one_entry_entry_valid():
    cache = build_lcmc()
    mock_entry = MagicMock(cache_key=sentinel.cache_key, valid=True, is_too_old=MagicMock(return_value=False))
    cache._cache[sentinel.cache_key] = sentinel.entry
    mock_reference = MagicMock(return_value=mock_entry)
    cache._lre_deque = MagicMock(pop=MagicMock(return_value=mock_reference))

    assert sentinel.cache_key in cache._cache
    cache._try_to_evict_one_entry()

    assert sentinel.cache_key in cache._cache
    cache._lre_deque.appendleft.assert_called_once_with(mock_reference)


@pytest.yield_fixture
def patch_try_to_evict_one_entry(mocker):
    mocker.patch.object(LocalCryptoMaterialsCache, "_try_to_evict_one_entry")
    yield LocalCryptoMaterialsCache._try_to_evict_one_entry


def test_try_to_evict_some_entries(patch_try_to_evict_one_entry):
    cache = build_lcmc()

    cache._try_to_evict_some_entries()

    patch_try_to_evict_one_entry.assert_has_calls([call() for _ in range(_OPPORTUNISTIC_EVICTION_ROUNDS)])


def test_prune(patch_try_to_evict_one_entry):
    cache = build_lcmc(capacity=2)
    mock_a = MagicMock()
    mock_d = MagicMock()
    cache._cache[sentinel.a] = mock_a
    cache._cache[sentinel.c] = mock_d
    cache._cache[sentinel.d] = sentinel.e
    cache._cache[sentinel.f] = sentinel.g

    cache._prune()

    assert len(cache._cache) == 2
    assert sentinel.a not in cache._cache
    assert sentinel.c not in cache._cache
    mock_a.invalidate.assert_called_once_with()
    mock_d.invalidate.assert_called_once_with()
    patch_try_to_evict_one_entry.assert_has_calls((call(), call()))


@pytest.yield_fixture
def patch_prune(mocker):
    mocker.patch.object(LocalCryptoMaterialsCache, "_prune")
    yield LocalCryptoMaterialsCache._prune


def test_add_value_to_cache(patch_prune):
    mock_entry = MagicMock(cache_key=sentinel.cache_key)
    mock_reference = weakref.ref(mock_entry)
    cache = build_lcmc()

    cache._add_value_to_cache(mock_entry)

    assert cache._cache[sentinel.cache_key] == mock_entry
    assert mock_reference in cache._lre_deque
    patch_prune.assert_called_once_with()


@pytest.yield_fixture
def patch_try_to_evict_some_entries(mocker):
    mocker.patch.object(LocalCryptoMaterialsCache, "_try_to_evict_some_entries")
    yield LocalCryptoMaterialsCache._try_to_evict_some_entries


@pytest.yield_fixture
def patch_add_value_to_cache(mocker):
    mocker.patch.object(LocalCryptoMaterialsCache, "_add_value_to_cache")
    yield LocalCryptoMaterialsCache._add_value_to_cache


@pytest.yield_fixture
def patch_crypto_cache_entry(mocker):
    mocker.patch.object(aws_encryption_sdk.caches.local, "CryptoMaterialsCacheEntry")
    yield aws_encryption_sdk.caches.local.CryptoMaterialsCacheEntry


def test_put_encryption_materials(patch_add_value_to_cache, patch_try_to_evict_some_entries, patch_crypto_cache_entry):
    cache = build_lcmc()

    cache.put_encryption_materials(
        cache_key=sentinel.cache_key,
        encryption_materials=sentinel.encryption_materials,
        plaintext_length=sentinel.plaintext_length,
        entry_hints=sentinel.entry_hints,
    )

    patch_crypto_cache_entry.assert_called_once_with(
        cache_key=sentinel.cache_key, value=sentinel.encryption_materials, hints=sentinel.entry_hints
    )
    patch_crypto_cache_entry.return_value._update_with_message_bytes_encrypted.assert_called_once_with(
        sentinel.plaintext_length
    )
    patch_try_to_evict_some_entries.assert_called_once_with()
    patch_add_value_to_cache.assert_called_once_with(patch_crypto_cache_entry.return_value)


def test_put_decryption_materials(patch_add_value_to_cache, patch_try_to_evict_some_entries, patch_crypto_cache_entry):
    cache = build_lcmc()

    cache.put_decryption_materials(cache_key=sentinel.cache_key, decryption_materials=sentinel.decryption_materials)

    patch_crypto_cache_entry.assert_called_once_with(cache_key=sentinel.cache_key, value=sentinel.decryption_materials)
    patch_try_to_evict_some_entries.assert_called_once_with()
    patch_add_value_to_cache.assert_called_once_with(patch_crypto_cache_entry.return_value)


def test_remove_key_not_found():
    cache = build_lcmc()

    assert sentinel.cache_key not in cache._cache
    with pytest.raises(CacheKeyError) as excinfo:
        cache.remove(MagicMock(cache_key=sentinel.cache_key))

    excinfo.match(r"Key not found in cache")


def test_remove_success():
    cache = build_lcmc()
    mock_entry = MagicMock(cache_key=sentinel.cache_key)
    cache._cache[sentinel.cache_key] = mock_entry

    cache.remove(mock_entry)

    mock_entry.invalidate.assert_called_once_with()
    assert sentinel.value not in cache._cache


@pytest.yield_fixture
def patch_remove(mocker):
    mocker.patch.object(LocalCryptoMaterialsCache, "remove")
    yield LocalCryptoMaterialsCache.remove


def test_get_single_entry_cache_miss(patch_remove):
    cache = build_lcmc()

    assert sentinel.cache_key not in cache._cache
    with pytest.raises(CacheKeyError) as excinfo:
        cache._get_single_entry(sentinel.cache_key)

    excinfo.match(r"Key not found in cache")
    assert not patch_remove.called


def test_get_single_entry_cache_hit_invalid(patch_remove):
    cache = build_lcmc()
    mock_entry = MagicMock(valid=False)
    cache._cache[sentinel.cache_key] = mock_entry

    with pytest.raises(CacheKeyError) as excinfo:
        cache._get_single_entry(sentinel.cache_key)

    patch_remove.assert_called_once_with(mock_entry)
    excinfo.match(r"Key not found in cache")


def test_get_single_entry_cache_hit_valid():
    cache = build_lcmc()
    mock_entry = MagicMock(valid=True)
    cache._cache[sentinel.cache_key] = mock_entry

    test = cache._get_single_entry(sentinel.cache_key)

    assert test is mock_entry


@pytest.yield_fixture
def patch_get_single_entry(mocker):
    mocker.patch.object(LocalCryptoMaterialsCache, "_get_single_entry")
    yield LocalCryptoMaterialsCache._get_single_entry


def test_get_encryption_materials(patch_get_single_entry):
    cache = build_lcmc()

    sentinel.plaintext_length = int()

    test = cache.get_encryption_materials(cache_key=sentinel.cache_key, plaintext_length=sentinel.plaintext_length)

    patch_get_single_entry.assert_called_once_with(sentinel.cache_key)
    patch_get_single_entry.return_value._update_with_message_bytes_encrypted.assert_called_once_with(
        sentinel.plaintext_length
    )
    assert test is patch_get_single_entry.return_value


def test_get_decryption_materials(patch_get_single_entry):
    cache = build_lcmc()

    test = cache._get_single_entry(sentinel.cache_key)

    patch_get_single_entry.assert_called_once_with(sentinel.cache_key)
    assert test is patch_get_single_entry.return_value


def test_clear():
    cache = build_lcmc()
    cache._cache = sentinel.cache
    cache._lre_deque = sentinel.lre

    cache.clear()

    assert cache._cache == OrderedDict()
    assert cache._lre_deque == deque()
