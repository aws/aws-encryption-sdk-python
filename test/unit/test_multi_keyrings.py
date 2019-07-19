# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit tests for Multi keyring."""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.identifiers import WrappingAlgorithm
from aws_encryption_sdk.keyring.multi_keyring import MultiKeyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring, RawRSAKeyring

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY_AES = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"

_SIGNING_KEY = b"aws-crypto-public-key"

_raw_rsa_keyring_1 = RawRSAKeyring(
    key_namespace=_PROVIDER_ID,
    key_name=_KEY_ID,
    wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
)

_raw_rsa_keyring_2 = RawRSAKeyring(
    key_namespace=_PROVIDER_ID,
    key_name=_KEY_ID,
    wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
)

_raw_aes_keyring = RawAESKeyring(
    key_namespace=_PROVIDER_ID,
    key_name=_KEY_ID,
    wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
    wrapping_key=_WRAPPING_KEY_AES,
)

_multi_keyring_no_children = MultiKeyring(
    generator=RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
    )
)

_multi_keyring_no_generator = MultiKeyring(
    children=[
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
        ),
        RawAESKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=_WRAPPING_KEY_AES,
        ),
    ]
)

_multi_keyring = MultiKeyring(
    generator=RawAESKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
        wrapping_key=_WRAPPING_KEY_AES,
    ),
    children=[
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
        ),
        RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
        ),
    ],
)

# _multi_keyring_null = MultiKeyring()

# _multi_keyring_children_not_keyrings = MultiKeyring(
#     generator=RawAESKeyring(
#         key_namespace=_PROVIDER_ID,
#         key_name=_KEY_ID,
#         wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
#         wrapping_key=_WRAPPING_KEY_AES,
#     ),
#     children=[
#         RawRSAKeyring(
#             key_namespace=_PROVIDER_ID,
#             key_name=_KEY_ID,
#             wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
#             wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
#         ),
#         WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
#     ],
# )


# def test_null_multi_keyring():
#     class NullMultiKeyring(_multi_keyring_null):
#         assert pytest.raises(TypeError)

# with pytest.raises(TypeError) as exc_info:
#     NullMultiKeyring()
# assert exc_info.match("At least one of generator or children must be provided")


# def test_no_generator_multi_keyring():
#     class NoGeneratorKeyring(_multi_keyring_no_generator):
#         assert not pytest.raises(TypeError)
#
#
# def test_no_children_multi_keyring():
#     class NoChildrenKeyring(_multi_keyring_no_children):
#         assert not pytest.raises(TypeError)


# def test_children_not_keyrings():
#     class ChildrenNotKeyrings(_multi_keyring_children_not_keyrings):
#         pass
#
#     with pytest.raises(TypeError) as exc_info:
#         ChildrenNotKeyrings()
#     assert exc_info.match("Children must me a keyring")
