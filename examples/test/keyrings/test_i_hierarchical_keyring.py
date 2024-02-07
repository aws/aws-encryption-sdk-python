"""Unit test suite for the hierarchical keyring example."""
import pytest

from ..src.keyrings.hierarchical_keyring import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    key_store_table_name = "KeyStoreDdbTable"
    key_arn = "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
    encrypt_and_decrypt_with_keyring(key_store_table_name, key_store_table_name, key_arn)
