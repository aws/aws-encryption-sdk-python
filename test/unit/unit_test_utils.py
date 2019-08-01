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
"""Utility functions to handle common test framework functions."""
import copy
import io
import itertools
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.internal.utils.streams import InsistentReaderBytesIO
from aws_encryption_sdk.keyring.multi_keyring import MultiKeyring
from aws_encryption_sdk.keyring.raw_keyring import Keyring, RawAESKeyring, RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey


try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Iterable  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_SIGNING_KEY = b"aws-crypto-public-key"
_DATA_KEY = (
    b"\x00\xfa\x8c\xdd\x08Au\xc6\x92_4\xc5\xfb\x90\xaf\x8f\xa1D\xaf\xcc\xd25" b"\xa8\x0b\x0b\x16\x92\x91W\x01\xb7\x84"
)
_WRAPPING_KEY_AES = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"


class IdentityKeyring(Keyring):
    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        return decryption_materials


class OnlyGenerateKeyring(Keyring):
    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        if encryption_materials.data_encryption_key is None:
            key_provider = MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID)
            data_encryption_key = RawDataKey(
                key_provider=key_provider, data_key=os.urandom(encryption_materials.algorithm.kdf_input_len)
            )
            encryption_materials.add_data_encryption_key(
                data_encryption_key=data_encryption_key,
                keyring_trace=KeyringTrace(
                    wrapping_key=key_provider, flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY}
                ),
            )
        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        return decryption_materials


def get_encryption_materials_with_data_key():
    return EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
            )
        ],
    )


def get_encryption_materials_without_data_key():
    return EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    )


def get_encryption_materials_with_encrypted_data_key():
    return EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encrypted_data_keys=[
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
            )
        ],
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={
                    KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
                    KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY,
                },
            )
        ],
    )


def get_decryption_materials_with_data_key():
    return DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        verification_key=b"ex_verification_key",
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY},
            )
        ],
    )


def get_decryption_materials_without_data_key():
    return DecryptionMaterials(encryption_context=_ENCRYPTION_CONTEXT, verification_key=b"ex_verification_key")


def get_multi_keyring_with_generator_and_children():
    return MultiKeyring(
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
                private_wrapping_key=rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                ),
            ),
            RawRSAKeyring(
                key_namespace=_PROVIDER_ID,
                key_name=_KEY_ID,
                wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
                private_wrapping_key=rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                ),
            ),
        ],
    )


def get_multi_keyring_with_no_children():
    return MultiKeyring(
        generator=RawRSAKeyring(
            key_namespace=_PROVIDER_ID,
            key_name=_KEY_ID,
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            private_wrapping_key=rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            ),
        )
    )


def get_multi_keyring_with_no_generator():
    return MultiKeyring(
        children=[
            RawRSAKeyring(
                key_namespace=_PROVIDER_ID,
                key_name=_KEY_ID,
                wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
                private_wrapping_key=rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                ),
            ),
            RawAESKeyring(
                key_namespace=_PROVIDER_ID,
                key_name=_KEY_ID,
                wrapping_algorithm=WrappingAlgorithm.AES_128_GCM_IV12_TAG16_NO_PADDING,
                wrapping_key=_WRAPPING_KEY_AES,
            ),
        ]
    )


def all_valid_kwargs(valid_kwargs):
    valid = []
    for cls, kwargs_sets in valid_kwargs.items():
        for kwargs in kwargs_sets:
            valid.append((cls, kwargs))
    return valid


def all_invalid_kwargs(valid_kwargs, invalid_kwargs=None):
    if invalid_kwargs is None:
        invalid_kwargs = {}
    invalid = []
    for cls, kwargs_sets in valid_kwargs.items():
        if cls in invalid_kwargs:
            for _kwargs in invalid_kwargs[cls]:
                invalid.append((cls, _kwargs))
            continue

        kwargs = kwargs_sets[-1]
        for key in kwargs:
            _kwargs = copy.deepcopy(kwargs)
            _kwargs.update({key: None})
            invalid.append((cls, _kwargs))
    return invalid


def build_valid_kwargs_list(base, optional_kwargs):
    valid_kwargs = []
    options = optional_kwargs.items()
    for i in range(len(optional_kwargs)):
        for valid_options in itertools.combinations(options, i):
            _kwargs = base.copy()
            _kwargs.update(dict(valid_options))
            valid_kwargs.append(_kwargs)
    return valid_kwargs


class SometimesIncompleteReaderIO(io.BytesIO):
    def __init__(self, *args, **kwargs):
        self._read_counter = 0
        super(SometimesIncompleteReaderIO, self).__init__(*args, **kwargs)

    def read(self, size=-1):
        """Every other read request, return fewer than the requested number of bytes if more than one byte requested."""
        self._read_counter += 1
        if size > 1 and self._read_counter % 2 == 0:
            size //= 2
        return super(SometimesIncompleteReaderIO, self).read(size)


class NothingButRead(object):
    def __init__(self, data):
        self._data = io.BytesIO(data)

    def read(self, size=-1):
        return self._data.read(size)


class ExactlyTwoReads(SometimesIncompleteReaderIO):
    def read(self, size=-1):
        if self._read_counter >= 2:
            self.close()
        return super(ExactlyTwoReads, self).read(size)


class FailingTeller(object):
    def tell(self):
        raise IOError("Tell not allowed!")


def assert_prepped_stream_identity(prepped_stream, wrapped_type):
    # Check the wrapped stream
    assert isinstance(prepped_stream, wrapped_type)
    # Check the wrapping streams
    assert isinstance(prepped_stream, InsistentReaderBytesIO)
