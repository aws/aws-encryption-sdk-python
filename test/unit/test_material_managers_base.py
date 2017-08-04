"""Test suite for aws_encryption_sdk.materials_managers.base"""
import pytest

from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager


def test_abstracts():
    with pytest.raises(TypeError) as excinfo:
        CryptoMaterialsManager()

    excinfo.match(r"Can't instantiate abstract class CryptoMaterialsManager with abstract methods {}".format(
        ', '.join([
            'decrypt_materials',
            'get_encryption_materials'
        ])
    ))
