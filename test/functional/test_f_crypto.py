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
"""Functional test suite for Elliptic Curve static length signature calculation."""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

import aws_encryption_sdk
from aws_encryption_sdk.internal.crypto.authentication import Signer
from aws_encryption_sdk.internal.crypto.elliptic_curve import _ecc_static_length_signature


# Run several of each type to make get a high probability of forcing signature length correction
@pytest.mark.parametrize('algorithm', [
    aws_encryption_sdk.Algorithm.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 for i in range(10)
] + [
    aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 for i in range(10)
])
def test_ecc_static_length_signature(algorithm):
    private_key = ec.generate_private_key(
        curve=algorithm.signing_algorithm_info(),
        backend=default_backend()
    )
    hasher = hashes.Hash(
        algorithm.signing_hash_type(),
        backend=default_backend()
    )
    data = b'aifuhaw9fe48haw9e8cnavwp9e8fhaw9438fnhjzsudfvhnsa89w74fhp90se8rhgfi'
    hasher.update(data)
    digest = hasher.finalize()
    signature = _ecc_static_length_signature(
        key=private_key,
        algorithm=algorithm,
        digest=digest
    )
    assert len(signature) == algorithm.signature_len
    private_key.public_key().verify(
        signature=signature,
        data=data,
        signature_algorithm=ec.ECDSA(algorithm.signing_hash_type())
    )


def test_signer_key_bytes_cycle():
    key = ec.generate_private_key(
        curve=ec.SECP384R1,
        backend=default_backend()
    )
    signer = Signer(
        algorithm=aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        key=key
    )
    key_bytes = signer.key_bytes()
    new_signer = Signer.from_key_bytes(
        algorithm=aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        key_bytes=key_bytes
    )
    assert new_signer.key.private_numbers().private_value == signer.key.private_numbers().private_value
