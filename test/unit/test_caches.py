# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.caches common functions."""
import struct
from base64 import b64decode

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from aws_encryption_sdk.caches import (
    _512_BIT_PAD,
    _encrypted_data_keys_hash,
    _encryption_context_hash,
    build_decryption_materials_cache_key,
    build_encryption_materials_cache_key,
)
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy
from aws_encryption_sdk.materials_managers import DecryptionMaterialsRequest, EncryptionMaterialsRequest
from aws_encryption_sdk.structures import DataKey, MasterKeyInfo

pytestmark = [pytest.mark.unit, pytest.mark.local]


VALUES = {
    "basic": {
        "partition_name": b"c15b9079-6d0e-42b6-8784-5e804b025692",
        "encryption_context": {
            "empty": {
                "raw": {},
                "hash": b"z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==",
            },
            "full": {
                "raw": {"this": "is", "a": "non-empty", "encryption": "context"},
                "hash": b"BPo+2YlnLPXnDxikPiNjCAQdS5Mz829EAn69cRSW81y8OIBPpwlyXVO9kqgHveWu50S42UISPN82fw0H5k+BSQ==",
            },
        },
        "encrypted_data_keys": [
            {
                "key": DataKey(
                    key_provider=MasterKeyInfo(provider_id="this is a provider ID", key_info=b"this is some key info"),
                    data_key=b"super secret key!",
                    encrypted_data_key=b"super secret key, now with encryption!",
                ),
                "hash": b"TYoFeYuxns/FBlaw4dsRDOv25OCEKuZG9iXt5iEdJ8LU7n5glgkDAVxWUEYC4JKKykJdHkaVpxcDvNqS6UswiQ==",
            },
            {
                "key": DataKey(
                    key_provider=MasterKeyInfo(
                        provider_id="another provider ID!", key_info=b"this is some different key info"
                    ),
                    data_key=b"better super secret key!",
                    encrypted_data_key=b"better super secret key, now with encryption!",
                ),
                "hash": b"wSrDlPM2ocIj9MAtD94ULSR0Qrt1muBovBDRL+DsSTNphJEM3CZ/h3OyvYL8BR2EIXx0m7GYwv8dGtyZL2D87w==",
            },
        ],
    }
}
VALUES["cache_ids"] = {
    "encrypt": [
        {
            "components": {
                "partition_name": VALUES["basic"]["partition_name"],
                "algorithm": None,
                "encryption_context": VALUES["basic"]["encryption_context"]["empty"]["raw"],
                "commitment_policy": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            },
            "id": b"rkrFAso1YyPbOJbmwVMjrPw+wwLJT7xusn8tA8zMe9e3+OqbtfDueB7bvoKLU3fsmdUvZ6eMt7mBp1ThMMB25Q==",
        },
        {
            "components": {
                "partition_name": VALUES["basic"]["partition_name"],
                "algorithm": Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                "encryption_context": VALUES["basic"]["encryption_context"]["empty"]["raw"],
                "commitment_policy": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            },
            "id": b"3icBIkLK4V3fVwbm3zSxUdUQV6ZvZYUOLl8buN36g6gDMqAkghcGryxX7QiVABkW1JhB6GRp5z+bzbiuciBcKQ==",
        },
        {
            "components": {
                "partition_name": VALUES["basic"]["partition_name"],
                "algorithm": None,
                "encryption_context": VALUES["basic"]["encryption_context"]["full"]["raw"],
                "commitment_policy": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            },
            "id": b"IHiUHYOUVUEFTc3BcZPJDlsWct2Qy1A7JdfQl9sQoV/ILIbRpoz9q7RtGd/MlibaGl5ihE66cN8ygM8A5rtYbg==",
        },
        {
            "components": {
                "partition_name": VALUES["basic"]["partition_name"],
                "algorithm": Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                "encryption_context": VALUES["basic"]["encryption_context"]["full"]["raw"],
                "commitment_policy": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            },
            "id": b"mRNK7qhTb/kJiiyGPgAevp0gwFRcET4KeeNYwZHhoEDvSUzQiDgl8Of+YRDaVzKxAqpNBgcAuFXde9JlaRRsmw==",
        },
    ],
    "decrypt": [
        {
            "components": {
                "partition_name": VALUES["basic"]["partition_name"],
                "algorithm": Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
                "encrypted_data_keys": set([VALUES["basic"]["encrypted_data_keys"][0]["key"]]),
                "encryption_context": VALUES["basic"]["encryption_context"]["empty"]["raw"],
                "commitment_policy": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            },
            "id": b"n0zVzk9QIVxhz6ET+aJIKKOJNxtpGtSe1yAbu7WU5l272Iw/jmhlER4psDHJs9Mr8KYiIvLGSXzggNDCc23+9w==",
        },
        {
            "components": {
                "partition_name": VALUES["basic"]["partition_name"],
                "algorithm": Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                "encrypted_data_keys": {entry["key"] for entry in VALUES["basic"]["encrypted_data_keys"]},
                "encryption_context": VALUES["basic"]["encryption_context"]["full"]["raw"],
                "commitment_policy": CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
            },
            "id": b"+rtwUe38CGnczGmYu12iqGWHIyDyZ44EvYQ4S6ACmsgS8VaEpiw0RTGpDk6Z/7YYN/jVHOAcNKDyCNP8EmstFg==",
        },
    ],
}


@pytest.mark.parametrize(
    "encryption_context, result",
    [(entry["raw"], entry["hash"]) for entry in VALUES["basic"]["encryption_context"].values()],
)
def test_encryption_context_hash(encryption_context, result):
    hasher = hashes.Hash(hashes.SHA512(), backend=default_backend())
    assert _encryption_context_hash(hasher, encryption_context) == b64decode(result)


@pytest.mark.parametrize(
    "inner_request, result",
    [
        (
            dict(
                partition=scenario["components"]["partition_name"],
                request=EncryptionMaterialsRequest(
                    encryption_context=scenario["components"]["encryption_context"],
                    frame_length=0,
                    algorithm=scenario["components"]["algorithm"],
                    commitment_policy=scenario["components"]["commitment_policy"],
                ),
            ),
            scenario["id"],
        )
        for scenario in VALUES["cache_ids"]["encrypt"]
    ],
)
def test_build_encryption_materials_cache_key(inner_request, result):
    assert build_encryption_materials_cache_key(**inner_request) == b64decode(result)


@pytest.mark.parametrize(
    "encrypted_data_keys, result",
    (
        (set([VALUES["basic"]["encrypted_data_keys"][0]["key"]]), [VALUES["basic"]["encrypted_data_keys"][0]["hash"]]),
        (set([VALUES["basic"]["encrypted_data_keys"][1]["key"]]), [VALUES["basic"]["encrypted_data_keys"][1]["hash"]]),
        (
            [VALUES["basic"]["encrypted_data_keys"][1]["key"], VALUES["basic"]["encrypted_data_keys"][0]["key"]],
            [VALUES["basic"]["encrypted_data_keys"][0]["hash"], VALUES["basic"]["encrypted_data_keys"][1]["hash"]],
        ),
    ),
)
def test_encrypted_data_keys_hash(encrypted_data_keys, result):
    hasher = hashes.Hash(hashes.SHA512(), backend=default_backend())
    assert _encrypted_data_keys_hash(hasher, encrypted_data_keys) == b"".join([b64decode(each) for each in result])


@pytest.mark.parametrize(
    "inner_request, result",
    [
        (
            dict(
                partition=scenario["components"]["partition_name"],
                request=DecryptionMaterialsRequest(
                    algorithm=scenario["components"]["algorithm"],
                    encrypted_data_keys=scenario["components"]["encrypted_data_keys"],
                    encryption_context=scenario["components"]["encryption_context"],
                    commitment_policy=scenario["components"]["commitment_policy"],
                ),
            ),
            scenario["id"],
        )
        for scenario in VALUES["cache_ids"]["decrypt"]
    ],
)
def test_build_decryption_materials_cache_key(inner_request, result):
    assert build_decryption_materials_cache_key(**inner_request) == b64decode(result)


def test_512_bit_pad():
    assert _512_BIT_PAD == struct.pack(">64x")
