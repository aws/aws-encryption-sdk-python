"""Unit test suite for CryptoMaterialsCache"""
import pytest

from aws_encryption_sdk.caches.base import CryptoMaterialsCache


def test_abstracts():
    with pytest.raises(TypeError) as excinfo:
        CryptoMaterialsCache()

    excinfo.match(r"Can't instantiate abstract class CryptoMaterialsCache with abstract methods {}".format(
        ', '.join([
            'get_decryption_materials',
            'get_encryption_materials',
            'put_decryption_materials',
            'put_encryption_materials'
        ])
    ))
