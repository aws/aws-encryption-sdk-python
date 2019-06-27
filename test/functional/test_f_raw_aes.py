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
"""Functional tests for Raw AES keyring encryption decryption path."""

import pytest

# from aws_encryption_sdk.keyring.base import Keyring
from aws_encryption_sdk.keyring.raw_keyring import RawAESKeyring

pytestmark = [pytest.mark.functional, pytest.mark.local]

_PLAINTEXT_DATA_KEY = b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e('
_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"

# _ENCRYPTED_DATA_KEYS = [
#     {
#         "wrapping_key": (b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"),
#         "key_id": b"5325b043-5843-4629-869c-64794af77ada",
#         "key_info": (
#             b"5325b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80\x00\x00\x00\x0c\xe0h\xe2NT\x1c\xb8\x8f!\t\xc2\x94"
#         ),
#         "edk": (
#             b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p\xdb\xbf\x94\x86*Q\x06"
#             b"\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde"
#         ),
#     },
#     {
#         "wrapping_key": (
#             b"Q\xfd\xaa[\"\xb3\x00\xc3E\xc0\xa7\xba_\xea\x92'vS$\x12\xa4h\x04\xd8\xdf\x80\xce\x16\x0ca\x9c\xc7"
#         ),
#         "key_id": b"ead3f97e-49fe-48ce-be12-5c126c0d6adf",
#         "key_info": (
#             b"ead3f97e-49fe-48ce-be12-5c126c0d6adf\x00\x00\x00\x80\x00\x00\x00\x0c\xb6r9\x14Q\xd2\x0f\x02\x87\xcet\xec"
#         ),
#         "edk": (
#             b"\x86\xe2\x80\xc9\x7f\x93\x13\xdf\x8e\xcc\xde_\xa0\x88p\xa5\xd3\x1b\x1atqUW\x96\xfft\x85gB\xadjy\xedeQ\r"
#             b"\xebL\x17\xf7\xd85\xea7_\xb3\xdb\x99"
#         ),
#     },
# ]
# _EDK_MAP = {_key["key_id"]: _key for _key in _ENCRYPTED_DATA_KEYS}
#
# _ENCRYPTION_MATERIALS = {
#     ""
# }


class RawAESEncryptionDecryption(RawAESKeyring):

    key_namespace = _PROVIDER_ID
    key_name = attr.ib(hash=True, validator=attr.validators.instance_of(six.binary_type))
    _wrapping_key = attr.ib(hash=True, repr=False, validator=attr.validators.instance_of(WrappingKey))
    _wrapping_algorithm = attr.ib(repr=False, validator=attr.validators.instance_of(WrappingAlgorithm))




