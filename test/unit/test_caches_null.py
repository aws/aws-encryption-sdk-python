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
"""Unit testing suite for NullCryptoMaterialsCache"""
import pytest
from mock import MagicMock

from aws_encryption_sdk.caches import CryptoMaterialsCacheEntry
from aws_encryption_sdk.caches.null import NullCryptoMaterialsCache
from aws_encryption_sdk.exceptions import CacheKeyError
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_put_encryption_materials():
    cache_key = b"ex_cache_key"
    value = MagicMock(__class__=EncryptionMaterials)
    check_value = CryptoMaterialsCacheEntry(cache_key=cache_key, value=value)
    cache = NullCryptoMaterialsCache()

    test = cache.put_encryption_materials(
        cache_key=cache_key, encryption_materials=value, plaintext_length=0, entry_hints=None
    )

    assert test == check_value


def test_put_decryption_materials():
    cache_key = b"ex_cache_key"
    value = MagicMock(__class__=DecryptionMaterials)
    check_value = CryptoMaterialsCacheEntry(cache_key=cache_key, value=value)
    cache = NullCryptoMaterialsCache()

    test = cache.put_decryption_materials(cache_key=cache_key, decryption_materials=value)

    assert test == check_value


@pytest.mark.parametrize(
    "method_name, args", (("get_encryption_materials", (None, None)), ("get_decryption_materials", (None,)))
)
def test_gets(method_name, args):
    test = NullCryptoMaterialsCache()

    with pytest.raises(CacheKeyError) as excinfo:
        getattr(test, method_name)(*args)

    excinfo.match(r"Key not found in cache")
