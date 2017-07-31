"""Unit testing suite for NullCryptoMaterialsCache"""
from mock import MagicMock
import pytest

from aws_encryption_sdk.caches import CryptoMaterialsCacheEntry
from aws_encryption_sdk.caches.null import NullCryptoMaterialsCache
from aws_encryption_sdk.exceptions import CacheKeyError
from aws_encryption_sdk.materials_managers import EncryptionMaterials, DecryptionMaterials


def test_put_encryption_materials():
    cache_key = b'ex_cache_key'
    value = MagicMock(__class__=EncryptionMaterials)
    check_value = CryptoMaterialsCacheEntry(
        cache_key=cache_key,
        value=value
    )
    cache = NullCryptoMaterialsCache()

    test = cache.put_encryption_materials(
        cache_key=cache_key,
        encryption_materials=value,
        plaintext_length=0,
        entry_hints=None
    )

    assert test == check_value


def test_put_decryption_materials():
    cache_key = b'ex_cache_key'
    value = MagicMock(__class__=DecryptionMaterials)
    check_value = CryptoMaterialsCacheEntry(
        cache_key=cache_key,
        value=value
    )
    cache = NullCryptoMaterialsCache()

    test = cache.put_decryption_materials(
        cache_key=cache_key,
        decryption_materials=value
    )

    assert test == check_value


@pytest.mark.parametrize('method_name, args', (
    ('get_encryption_materials', (None, None)),
    ('get_decryption_materials', (None,))
))
def test_gets(method_name, args):
    test = NullCryptoMaterialsCache()

    with pytest.raises(CacheKeyError) as excinfo:
        getattr(test, method_name)(*args)

    excinfo.match(r'Key not found in cache')
