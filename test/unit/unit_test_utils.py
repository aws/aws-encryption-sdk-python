# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions to handle common test framework functions."""
import base64
import copy
import io
import itertools
import os

import attr
from attr.validators import instance_of
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.exceptions import DecryptKeyError
from aws_encryption_sdk.identifiers import AlgorithmSuite, EncryptionKeyType, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.internal.utils.streams import InsistentReaderBytesIO
from aws_encryption_sdk.key_providers.base import MasterKeyProvider, MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKey, RawMasterKeyProvider
from aws_encryption_sdk.keyrings.base import Keyring
from aws_encryption_sdk.keyrings.multi import MultiKeyring
from aws_encryption_sdk.keyrings.raw import RawAESKeyring, RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Iterable, Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_EXISTING_KEY_ID = b"pre-seeded key id"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_WRAPPING_KEY = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"
_SIGNING_KEY = b"aws-crypto-public-key"
_DATA_KEY = (
    b"\x00\xfa\x8c\xdd\x08Au\xc6\x92_4\xc5\xfb\x90\xaf\x8f\xa1D\xaf\xcc\xd25" b"\xa8\x0b\x0b\x16\x92\x91W\x01\xb7\x84"
)
_WRAPPING_KEY_AES = b"\xeby-\x80A6\x15rA8\x83#,\xe4\xab\xac`\xaf\x99Z\xc1\xce\xdb\xb6\x0f\xb7\x805\xb2\x14J3"

_PUBLIC_EXPONENT = 65537
_KEY_SIZE = 2048
_BACKEND = default_backend()

_ENCRYPTED_DATA_KEY_AES = EncryptedDataKey(
    key_provider=MasterKeyInfo(
        provider_id="Random Raw Keys",
        key_info=b"5325b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80"
        b"\x00\x00\x00\x0c\xc7\xd5d\xc9\xc5\xf21\x8d\x8b\xf9H"
        b"\xbb",
    ),
    encrypted_data_key=b"\xf3+\x15n\xe6`\xbe\xfe\xf0\x9e1\xe5\x9b"
    b"\xaf\xfe\xdaT\xbb\x17\x14\xfd} o\xdd\xf1"
    b"\xbc\xe1C\xa5J\xd8\xc7\x15\xc2\x90t=\xb9"
    b"\xfd;\x94lTu/6\xfe",
)

_ENCRYPTED_DATA_KEY_NOT_IN_KEYRING = EncryptedDataKey(
    key_provider=MasterKeyInfo(
        provider_id="Random Raw Keys",
        key_info=b"5430b043-5843-4629-869c-64794af77ada\x00\x00\x00\x80"
        b"\x00\x00\x00\x0c\xc7\xd5d\xc9\xc5\xf21\x8d\x8b\xf9H"
        b"\xbb",
    ),
    encrypted_data_key=b"\xf3+\x15n\xe6`\xbe\xfe\xf0\x9e1\xe5\x9b"
    b"\xaf\xfe\xdaT\xbb\x17\x14\xfd} o\xdd\xf1"
    b"\xbc\xe1C\xa5J\xd8\xc7\x15\xc2\x90t=\xb9"
    b"\xfd;\x94lTu/6\xfe",
)

_ENCRYPTED_DATA_KEY_RSA = EncryptedDataKey(
    key_provider=MasterKeyInfo(provider_id="Random Raw Keys", key_info=_KEY_ID),
    encrypted_data_key=b"\xf3+\x15n\xe6`\xbe\xfe\xf0\x9e1\xe5\x9b"
    b"\xaf\xfe\xdaT\xbb\x17\x14\xfd} o\xdd\xf1"
    b"\xbc\xe1C\xa5J\xd8\xc7\x15\xc2\x90t=\xb9"
    b"\xfd;\x94lTu/6\xfe",
)


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
            encryption_materials = encryption_materials.with_data_encryption_key(
                data_encryption_key=data_encryption_key,
                keyring_trace=KeyringTrace(wrapping_key=key_provider, flags={KeyringTraceFlag.GENERATED_DATA_KEY}),
            )
        return encryption_materials

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        return decryption_materials


def get_encryption_materials_with_data_key():
    return EncryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                flags={KeyringTraceFlag.GENERATED_DATA_KEY},
            )
        ],
    )


def get_encryption_materials_with_data_encryption_key():
    return EncryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                flags={KeyringTraceFlag.GENERATED_DATA_KEY},
            )
        ],
    )


def get_encryption_materials_without_data_key():
    return EncryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    )


def get_encryption_materials_with_encrypted_data_key():
    return EncryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encrypted_data_keys=[
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
            )
        ],
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                flags={KeyringTraceFlag.GENERATED_DATA_KEY, KeyringTraceFlag.ENCRYPTED_DATA_KEY},
            )
        ],
    )


def get_encryption_materials_with_encrypted_data_key_aes():
    return EncryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encrypted_data_keys=[_ENCRYPTED_DATA_KEY_AES],
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                flags={KeyringTraceFlag.GENERATED_DATA_KEY, KeyringTraceFlag.ENCRYPTED_DATA_KEY},
            )
        ],
    )


def get_encryption_materials_without_data_encryption_key():
    return EncryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    )


def get_decryption_materials_without_data_encryption_key():
    return DecryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        verification_key=b"ex_verification_key",
        encryption_context=_ENCRYPTION_CONTEXT,
    )


def get_decryption_materials_with_data_key():
    return DecryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        verification_key=b"ex_verification_key",
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                flags={KeyringTraceFlag.DECRYPTED_DATA_KEY},
            )
        ],
    )


def get_decryption_materials_with_data_encryption_key():
    return DecryptionMaterials(
        algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        verification_key=b"ex_verification_key",
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_EXISTING_KEY_ID),
                flags={KeyringTraceFlag.DECRYPTED_DATA_KEY},
            )
        ],
    )


def get_decryption_materials_without_data_key():
    return DecryptionMaterials(encryption_context=_ENCRYPTION_CONTEXT, verification_key=b"ex_verification_key")


def get_multi_keyring_with_generator_and_children():
    return MultiKeyring(
        generator=RawAESKeyring(key_namespace=_PROVIDER_ID, key_name=_KEY_ID, wrapping_key=_WRAPPING_KEY_AES,),
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
            RawAESKeyring(key_namespace=_PROVIDER_ID, key_name=_KEY_ID, wrapping_key=_WRAPPING_KEY_AES,),
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


def _generate_rsa_key_bytes(size):
    # type: (int) -> bytes
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size, backend=default_backend())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ephemeral_raw_rsa_master_key(size=4096):
    # type: (int) -> RawMasterKey
    key_bytes = _generate_rsa_key_bytes(size)
    return RawMasterKey(
        provider_id="fake",
        key_id="rsa-{}".format(size).encode("utf-8"),
        wrapping_key=WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
            wrapping_key=key_bytes,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
        ),
    )


def ephemeral_raw_rsa_keyring(size=4096, wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1):
    # type: (int, WrappingAlgorithm) -> RawRSAKeyring
    key_bytes = _generate_rsa_key_bytes(size)
    return RawRSAKeyring.from_pem_encoding(
        key_namespace="fake",
        key_name="rsa-{}".format(size).encode("utf-8"),
        wrapping_algorithm=wrapping_algorithm,
        private_encoded_key=key_bytes,
    )


def raw_rsa_mkps_from_keyring(keyring):
    # type: (RawRSAKeyring) -> (MasterKeyProvider, MasterKeyProvider)
    """Constructs a private and public raw RSA MKP using the private key in the raw RSA keyring."""
    private_key = keyring._private_wrapping_key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key_mkp = RawMasterKey(
        provider_id=keyring.key_namespace,
        key_id=keyring.key_name,
        wrapping_key=WrappingKey(
            wrapping_algorithm=keyring._wrapping_algorithm,
            wrapping_key=private_pem,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
        ),
    )
    public_key_mkp = RawMasterKey(
        provider_id=keyring.key_namespace,
        key_id=keyring.key_name,
        wrapping_key=WrappingKey(
            wrapping_algorithm=keyring._wrapping_algorithm,
            wrapping_key=public_pem,
            wrapping_key_type=EncryptionKeyType.PUBLIC,
        ),
    )
    return private_key_mkp, public_key_mkp


def ephemeral_raw_aes_master_key(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING, key=None):
    # type: (WrappingAlgorithm, Optional[bytes]) -> RawMasterKey
    key_length = wrapping_algorithm.algorithm.data_key_len
    if key is None:
        key = os.urandom(key_length)
    return RawMasterKey(
        provider_id="fake",
        key_id="aes-{}".format(key_length * 8).encode("utf-8"),
        wrapping_key=WrappingKey(
            wrapping_algorithm=wrapping_algorithm, wrapping_key=key, wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        ),
    )


def ephemeral_raw_aes_keyring(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING, key=None):
    # type: (WrappingAlgorithm, Optional[bytes]) -> RawAESKeyring
    key_length = wrapping_algorithm.algorithm.data_key_len
    if key is None:
        key = os.urandom(key_length)
    return RawAESKeyring(
        key_namespace="fake", key_name="aes-{}".format(key_length * 8).encode("utf-8"), wrapping_key=key,
    )


class EphemeralRawMasterKeyProvider(RawMasterKeyProvider):
    """Master key provider with raw master keys that are generated on each initialization."""

    provider_id = "fake"

    def __init__(self):
        self.__keys = {
            b"aes-256": ephemeral_raw_aes_master_key(WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING),
            b"rsa-4096": ephemeral_raw_rsa_master_key(4096),
        }

    def _get_raw_key(self, key_id):
        return self.__keys[key_id].config.wrapping_key


class EmptyMasterKeyProvider(MasterKeyProvider):
    """Master key provider that provides no master keys."""

    provider_id = "empty"
    _config_class = MasterKeyProviderConfig
    vend_masterkey_on_decrypt = False

    def _new_master_key(self, key_id):
        raise Exception("How did this happen??")

    def master_keys_for_encryption(self, encryption_context, plaintext_rostream, plaintext_length=None):
        return ephemeral_raw_aes_master_key(), []


class DisjointMasterKeyProvider(MasterKeyProvider):
    """Master key provider that does not provide the primary master key in the additional master keys."""

    provider_id = "disjoint"
    _config_class = MasterKeyProviderConfig
    vend_masterkey_on_decrypt = False

    def _new_master_key(self, key_id):
        raise Exception("How did this happen??")

    def master_keys_for_encryption(self, encryption_context, plaintext_rostream, plaintext_length=None):
        return ephemeral_raw_aes_master_key(), [ephemeral_raw_rsa_master_key()]


class FailingDecryptMasterKeyProvider(EphemeralRawMasterKeyProvider):
    """EphemeralRawMasterKeyProvider that cannot decrypt."""

    def decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        raise DecryptKeyError("FailingDecryptMasterKeyProvider cannot decrypt!")


@attr.s
class BrokenKeyring(Keyring):
    """Keyring that wraps another keyring and selectively breaks the returned values."""

    _inner_keyring = attr.ib(validator=instance_of(Keyring))
    _break_algorithm = attr.ib(default=False, validator=instance_of(bool))
    _break_encryption_context = attr.ib(default=False, validator=instance_of(bool))
    _break_signing = attr.ib(default=False, validator=instance_of(bool))

    @staticmethod
    def _random_string(bytes_len):
        # type: (int) -> str
        return base64.b64encode(os.urandom(bytes_len)).decode("utf-8")

    def _broken_algorithm(self, algorithm):
        # type: (AlgorithmSuite) -> AlgorithmSuite
        if not self._break_algorithm:
            return algorithm

        # We want to make sure that we return something different,
        #  so find this suite in all suites and grab the next one,
        #  whatever that is.
        all_suites = list(AlgorithmSuite)
        suite_index = all_suites.index(algorithm)
        next_index = (suite_index + 1) % (len(all_suites) - 1)

        return all_suites[next_index]

    def _broken_encryption_context(self, encryption_context):
        # type: (Dict[str, str]) -> Dict[str, str]
        broken_ec = encryption_context.copy()

        if not self._break_encryption_context:
            return broken_ec

        # Remove a random value
        try:
            broken_ec.popitem()
        except KeyError:
            pass

        # add a random value
        broken_ec[self._random_string(5)] = self._random_string(10)

        return broken_ec

    def _broken_key(self, key):
        # type: (bytes) -> bytes
        if not self._break_signing:
            return key

        return self._random_string(32).encode("utf-8")

    def _break_encryption_materials(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        return EncryptionMaterials(
            algorithm=self._broken_algorithm(encryption_materials.algorithm),
            data_encryption_key=encryption_materials.data_encryption_key,
            encrypted_data_keys=encryption_materials.encrypted_data_keys,
            encryption_context=self._broken_encryption_context(encryption_materials.encryption_context),
            signing_key=self._broken_key(encryption_materials.signing_key),
            keyring_trace=encryption_materials.keyring_trace,
        )

    def _break_decryption_materials(self, decryption_materials):
        # type: (DecryptionMaterials) -> DecryptionMaterials
        return DecryptionMaterials(
            algorithm=self._broken_algorithm(decryption_materials.algorithm),
            data_encryption_key=decryption_materials.data_encryption_key,
            encryption_context=self._broken_encryption_context(decryption_materials.encryption_context),
            verification_key=self._broken_key(decryption_materials.verification_key),
            keyring_trace=decryption_materials.keyring_trace,
        )

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        return self._break_encryption_materials(self._inner_keyring.on_encrypt(encryption_materials))

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        return self._break_decryption_materials(
            self._inner_keyring.on_decrypt(decryption_materials, encrypted_data_keys)
        )


@attr.s
class NoEncryptedDataKeysKeyring(Keyring):
    """Keyring that wraps another keyring and removes any encrypted data keys."""

    _inner_keyring = attr.ib(validator=instance_of(Keyring))

    def on_encrypt(self, encryption_materials):
        # type: (EncryptionMaterials) -> EncryptionMaterials
        materials = self._inner_keyring.on_encrypt(encryption_materials)
        return EncryptionMaterials(
            algorithm=materials.algorithm,
            data_encryption_key=materials.data_encryption_key,
            encryption_context=materials.encryption_context,
            signing_key=materials.signing_key,
            keyring_trace=materials.keyring_trace,
        )

    def on_decrypt(self, decryption_materials, encrypted_data_keys):
        # type: (DecryptionMaterials, Iterable[EncryptedDataKey]) -> DecryptionMaterials
        return self._inner_keyring.on_decrypt(decryption_materials, encrypted_data_keys)
