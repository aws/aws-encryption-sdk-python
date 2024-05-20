# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for ``aws_encryption_sdk.key_providers.base``."""
import itertools

import attr
import pytest

from aws_encryption_sdk.exceptions import InvalidKeyIdError
from aws_encryption_sdk.identifiers import AlgorithmSuite, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKey, RawMasterKeyProvider, WrappingKey
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

pytestmark = [pytest.mark.functional, pytest.mark.local]


_PLAINTEXT_DATA_KEY = b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e('
_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_ENCRYPTED_DATA_KEYS = [
    {
        "wrapping_key": (b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"),
        "key_id": b"5325b043-5843-4629-869c-64794af77ada",
        "key_info": (
            b"5325b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80\x00\x00\x00\x0c\xe0h\xe2NT\x1c\xb8\x8f!\t\xc2\x94"
        ),
        "edk": (
            b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p\xdb\xbf\x94\x86*Q\x06"
            b"\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde"
        ),
    },
    {
        "wrapping_key": (
            b"Q\xfd\xaa[\"\xb3\x00\xc3E\xc0\xa7\xba_\xea\x92'vS$\x12\xa4h\x04\xd8\xdf\x80\xce\x16\x0ca\x9c\xc7"
        ),
        "key_id": b"ead3f97e-49fe-48ce-be12-5c126c0d6adf",
        "key_info": (
            b"ead3f97e-49fe-48ce-be12-5c126c0d6adf\x00\x00\x00\x80\x00\x00\x00\x0c\xb6r9\x14Q\xd2\x0f\x02\x87\xcet\xec"
        ),
        "edk": (
            b"\x86\xe2\x80\xc9\x7f\x93\x13\xdf\x8e\xcc\xde_\xa0\x88p\xa5\xd3\x1b\x1atqUW\x96\xfft\x85gB\xadjy\xedeQ\r"
            b"\xebL\x17\xf7\xd85\xea7_\xb3\xdb\x99"
        ),
    },
]
_EDK_MAP = {_key["key_id"]: _key for _key in _ENCRYPTED_DATA_KEYS}


class RawMultiMKP(RawMasterKeyProvider):
    @attr.s
    class _RawMultiMKPConfig(MasterKeyProviderConfig):
        valid_key_ids = attr.ib()

    def __init__(self, *args, **kwargs):
        for key_id in self.config.valid_key_ids:
            self.add_master_key(key_id)

    provider_id = _PROVIDER_ID
    _config_class = _RawMultiMKPConfig

    def _get_raw_key(self, key_id):
        if key_id in self.config.valid_key_ids:
            return WrappingKey(
                wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                wrapping_key=_EDK_MAP[key_id]["wrapping_key"],
                wrapping_key_type=EncryptionKeyType.SYMMETRIC,
            )

        raise InvalidKeyIdError("Unknown key id")


def _keys_to_mkp(keys):
    if len(keys) > 1:
        return RawMultiMKP(valid_key_ids=[key["key_id"] for key in keys])

    _key = keys[0]
    return RawMasterKey(
        provider_id=_PROVIDER_ID,
        key_id=_key["key_id"],
        wrapping_key=WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=_key["wrapping_key"],
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        ),
    )


def _edk_cobinations():
    _edks = [
        EncryptedDataKey(key_provider=MasterKeyInfo(_PROVIDER_ID, edk["key_info"]), encrypted_data_key=edk["edk"])
        for edk in _ENCRYPTED_DATA_KEYS
    ]
    edks = itertools.permutations(_edks)

    mkps = [
        _keys_to_mkp(_keys)
        for _keys in itertools.chain.from_iterable(
            [itertools.permutations(_ENCRYPTED_DATA_KEYS, i) for i in range(1, len(_ENCRYPTED_DATA_KEYS) + 1)]
        )
    ]

    for edk_group, mkp_group in itertools.product(edks, mkps):
        yield mkp_group, edk_group


@pytest.mark.parametrize("mkp, edks", _edk_cobinations())
def test_decrypt_data_keys(mkp, edks):
    # type: (RawMasterKey, Iterable[EncryptedDataKey]) -> None
    data_key = mkp.decrypt_data_key_from_list(
        encrypted_data_keys=edks,
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
    )
    assert data_key.data_key == _PLAINTEXT_DATA_KEY
