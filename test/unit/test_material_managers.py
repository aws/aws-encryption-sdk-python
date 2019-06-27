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
"""Test suite for aws_encryption_sdk.materials_managers"""
import pytest
from mock import MagicMock
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk.exceptions import InvalidDataKeyError, InvalidKeyringTraceError, SignatureKeyError
from aws_encryption_sdk.identifiers import AlgorithmSuite, KeyringTraceFlag
from aws_encryption_sdk.internal.defaults import ALGORITHM
from aws_encryption_sdk.internal.utils.streams import ROStream
from aws_encryption_sdk.materials_managers import (
    CryptographicMaterials,
    DecryptionMaterials,
    DecryptionMaterialsRequest,
    EncryptionMaterials,
    EncryptionMaterialsRequest,
    _data_key_to_raw_data_key,
)
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.unit, pytest.mark.local]

_DATA_KEY = DataKey(
    key_provider=MasterKeyInfo(provider_id="Provider", key_info=b"Info"),
    data_key=b"1234567890123456789012",
    encrypted_data_key=b"asdf",
)
_RAW_DATA_KEY = RawDataKey.from_data_key(_DATA_KEY)
_ENCRYPTED_DATA_KEY = EncryptedDataKey.from_data_key(_DATA_KEY)

_VALID_KWARGS = {
    "CryptographicMaterials": dict(
        algorithm=ALGORITHM,
        encryption_context={"additional": "data"},
        data_encryption_key=_DATA_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id="Provider", key_info=b"Info"),
                flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
            )
        ],
    ),
    "EncryptionMaterialsRequest": dict(
        encryption_context={},
        plaintext_rostream=MagicMock(__class__=ROStream),
        frame_length=5,
        algorithm=ALGORITHM,
        plaintext_length=5,
    ),
    "EncryptionMaterials": dict(
        algorithm=ALGORITHM,
        data_encryption_key=_DATA_KEY,
        encrypted_data_keys=set([]),
        encryption_context={},
        signing_key=b"",
    ),
    "DecryptionMaterialsRequest": dict(algorithm=ALGORITHM, encrypted_data_keys=set([]), encryption_context={}),
    "DecryptionMaterials": dict(
        data_key=_DATA_KEY, verification_key=b"ex_verification_key", algorithm=ALGORITHM, encryption_context={}
    ),
}
_REMOVE = object()


def _copy_and_update_kwargs(class_name, mod_kwargs):
    kwargs = _VALID_KWARGS[class_name].copy()
    kwargs.update(mod_kwargs)
    purge_keys = [key for key, val in kwargs.items() if val is _REMOVE]
    for key in purge_keys:
        del kwargs[key]
    return kwargs


@pytest.mark.parametrize(
    "attr_class, invalid_kwargs",
    (
        (CryptographicMaterials, dict(algorithm=1234)),
        (CryptographicMaterials, dict(encryption_context=1234)),
        (CryptographicMaterials, dict(data_encryption_key=1234)),
        (CryptographicMaterials, dict(encrypted_data_keys=1234)),
        (CryptographicMaterials, dict(keyring_trace=1234)),
        (EncryptionMaterialsRequest, dict(encryption_context=None)),
        (EncryptionMaterialsRequest, dict(frame_length="not an int")),
        (EncryptionMaterialsRequest, dict(algorithm="not an Algorithm or None")),
        (EncryptionMaterialsRequest, dict(plaintext_length="not an int or None")),
        (EncryptionMaterials, dict(algorithm=None)),
        (EncryptionMaterials, dict(encryption_context=None)),
        (EncryptionMaterials, dict(signing_key=u"not bytes or None")),
        (DecryptionMaterialsRequest, dict(algorithm=None)),
        (DecryptionMaterialsRequest, dict(encrypted_data_keys=None)),
        (DecryptionMaterialsRequest, dict(encryption_context=None)),
        (DecryptionMaterials, dict(verification_key=5555)),
        (DecryptionMaterials, dict(data_key=_DATA_KEY, data_encryption_key=_DATA_KEY)),
    ),
)
def test_attributes_fails(attr_class, invalid_kwargs):
    kwargs = _copy_and_update_kwargs(attr_class.__name__, invalid_kwargs)
    with pytest.raises(TypeError):
        attr_class(**kwargs)


@pytest.mark.parametrize(
    "attr_class, kwargs_modification",
    (
        (CryptographicMaterials, {}),
        (EncryptionMaterials, {}),
        (DecryptionMaterials, {}),
        (DecryptionMaterials, dict(data_key=_REMOVE, data_encryption_key=_REMOVE)),
        (DecryptionMaterials, dict(data_key=_REMOVE, data_encryption_key=_RAW_DATA_KEY)),
        (DecryptionMaterials, dict(data_key=_RAW_DATA_KEY, data_encryption_key=_REMOVE)),
    ),
)
def test_attributes_good(attr_class, kwargs_modification):
    kwargs = _copy_and_update_kwargs(attr_class.__name__, kwargs_modification)
    attr_class(**kwargs)


def test_encryption_materials_request_attributes_defaults():
    test = EncryptionMaterialsRequest(encryption_context={}, frame_length=5)
    assert test.plaintext_rostream is None
    assert test.algorithm is None
    assert test.plaintext_length is None


def test_encryption_materials_defaults():
    test = EncryptionMaterials(
        algorithm=ALGORITHM, data_encryption_key=_DATA_KEY, encrypted_data_keys=set([]), encryption_context={}
    )
    assert test.signing_key is None


def test_decryption_materials_defaults():
    test = DecryptionMaterials(data_key=_DATA_KEY)
    assert test.verification_key is None
    assert test.algorithm is None
    assert test.encryption_context is None


def test_decryption_materials_legacy_data_key_get():
    test = DecryptionMaterials(data_encryption_key=_DATA_KEY)

    assert test.data_encryption_key == _RAW_DATA_KEY
    assert test.data_key == _RAW_DATA_KEY


@pytest.mark.parametrize(
    "data_key, expected", ((_DATA_KEY, _RAW_DATA_KEY), (_RAW_DATA_KEY, _RAW_DATA_KEY), (None, None))
)
def test_data_key_to_raw_data_key_success(data_key, expected):
    test = _data_key_to_raw_data_key(data_key=data_key)

    assert test == expected


def test_data_key_to_raw_data_key_fail():
    with pytest.raises(TypeError) as excinfo:
        _data_key_to_raw_data_key(data_key="not a data key")

    excinfo.match("data_key must be type DataKey not str")


def _cryptographic_materials_attributes():
    for material in (CryptographicMaterials, EncryptionMaterials, DecryptionMaterials):
        for attribute in (
            "algorithm",
            "encryption_context",
            "data_encryption_key",
            "_keyring_trace",
            "keyring_trace",
            "_initialized",
        ):
            yield material, attribute

    for attribute in ("_encrypted_data_keys", "encrypted_data_keys", "signing_key"):
        yield EncryptionMaterials, attribute

    for attribute in ("data_key", "verification_key"):
        yield DecryptionMaterials, attribute


@pytest.mark.parametrize("material_class, attribute_name", _cryptographic_materials_attributes())
def test_cryptographic_materials_cannot_change_attribute(material_class, attribute_name):
    test = material_class(algorithm=ALGORITHM, encryption_context={})

    with pytest.raises(AttributeError) as excinfo:
        setattr(test, attribute_name, 42)

    excinfo.match("can't set attribute")


@pytest.mark.parametrize("material_class", (CryptographicMaterials, EncryptionMaterials, DecryptionMaterials))
def test_immutable_keyring_trace(material_class):
    materials = material_class(**_VALID_KWARGS[material_class.__name__])

    with pytest.raises(AttributeError):
        materials.keyring_trace.append(42)


def test_immutable_encrypted_data_keys():
    materials = EncryptionMaterials(**_VALID_KWARGS["EncryptionMaterials"])

    with pytest.raises(AttributeError):
        materials.encrypted_data_keys.add(42)


@pytest.mark.parametrize(
    "material_class, flag",
    (
        (EncryptionMaterials, KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY),
        (DecryptionMaterials, KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY),
    ),
)
def test_add_data_encryption_key_success(material_class, flag):
    kwargs = _copy_and_update_kwargs(material_class.__name__, dict(data_encryption_key=_REMOVE, data_key=_REMOVE))
    materials = material_class(**kwargs)

    materials.add_data_encryption_key(
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id="a", key_info=b"b"), data_key=b"1" * ALGORITHM.kdf_input_len
        ),
        keyring_trace=KeyringTrace(wrapping_key=MasterKeyInfo(provider_id="a", key_info=b"b"), flags={flag}),
    )


def _add_data_encryption_key_test_cases():
    for material_class, required_flags in (
        (EncryptionMaterials, KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY),
        (DecryptionMaterials, KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY),
    ):
        yield (
            material_class,
            dict(data_encryption_key=_RAW_DATA_KEY, data_key=_REMOVE),
            _RAW_DATA_KEY,
            KeyringTrace(wrapping_key=_RAW_DATA_KEY.key_provider, flags={required_flags}),
            AttributeError,
            "Data encryption key is already set.",
        )
        yield (
            material_class,
            dict(data_encryption_key=_REMOVE, data_key=_REMOVE),
            _RAW_DATA_KEY,
            KeyringTrace(wrapping_key=_RAW_DATA_KEY.key_provider, flags=set()),
            InvalidKeyringTraceError,
            "Keyring flags do not match action.",
        )
        yield (
            material_class,
            dict(data_encryption_key=_REMOVE, data_key=_REMOVE),
            RawDataKey(key_provider=MasterKeyInfo(provider_id="a", key_info=b"b"), data_key=b"asdf"),
            KeyringTrace(wrapping_key=MasterKeyInfo(provider_id="c", key_info=b"d"), flags={required_flags}),
            InvalidKeyringTraceError,
            "Keyring trace does not match data key provider.",
        )
        yield (
            material_class,
            dict(data_encryption_key=_REMOVE, data_key=_REMOVE),
            RawDataKey(key_provider=_RAW_DATA_KEY.key_provider, data_key=b"1234"),
            KeyringTrace(wrapping_key=_RAW_DATA_KEY.key_provider, flags={required_flags}),
            InvalidDataKeyError,
            r"Invalid data key length *",
        )


@pytest.mark.parametrize(
    "material_class, mod_kwargs, data_encryption_key, keyring_trace, exception_type, exception_message",
    _add_data_encryption_key_test_cases(),
)
def test_add_data_encryption_key_fail(
    material_class, mod_kwargs, data_encryption_key, keyring_trace, exception_type, exception_message
):
    kwargs = _copy_and_update_kwargs(material_class.__name__, mod_kwargs)
    materials = material_class(**kwargs)

    with pytest.raises(exception_type) as excinfo:
        materials.add_data_encryption_key(data_encryption_key=data_encryption_key, keyring_trace=keyring_trace)

    excinfo.match(exception_message)


def test_add_encrypted_data_key_success():
    kwargs = _copy_and_update_kwargs("EncryptionMaterials", {})
    materials = EncryptionMaterials(**kwargs)

    materials.add_encrypted_data_key(
        _ENCRYPTED_DATA_KEY,
        keyring_trace=KeyringTrace(
            wrapping_key=_ENCRYPTED_DATA_KEY.key_provider, flags={KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY}
        ),
    )


@pytest.mark.parametrize(
    "encrypted_data_key, keyring_trace, exception_type, exception_message",
    (
        (
            _ENCRYPTED_DATA_KEY,
            KeyringTrace(wrapping_key=_ENCRYPTED_DATA_KEY.key_provider, flags=set()),
            InvalidKeyringTraceError,
            "Keyring flags do not match action.",
        ),
        (
            EncryptedDataKey(key_provider=MasterKeyInfo(provider_id="a", key_info=b"b"), encrypted_data_key=b"asdf"),
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id="not a match", key_info=b"really not a match"),
                flags={KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY},
            ),
            InvalidKeyringTraceError,
            "Keyring trace does not match data key encryptor.",
        ),
    ),
)
def test_add_encrypted_data_key_fail(encrypted_data_key, keyring_trace, exception_type, exception_message):
    kwargs = _copy_and_update_kwargs("EncryptionMaterials", {})
    materials = EncryptionMaterials(**kwargs)

    with pytest.raises(exception_type) as excinfo:
        materials.add_encrypted_data_key(encrypted_data_key=encrypted_data_key, keyring_trace=keyring_trace)

    excinfo.match(exception_message)


def test_add_signing_key_success():
    kwargs = _copy_and_update_kwargs("EncryptionMaterials", dict(signing_key=_REMOVE))
    materials = EncryptionMaterials(**kwargs)

    materials.add_signing_key(signing_key=b"")


@pytest.mark.parametrize(
    "mod_kwargs, signing_key, exception_type, exception_message",
    (
        ({}, b"", AttributeError, "Signing key is already set."),
        (
            dict(signing_key=_REMOVE, algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16),
            b"",
            SignatureKeyError,
            "Algorithm suite does not support signing keys.",
        ),
    ),
)
def test_add_signing_key_fail(mod_kwargs, signing_key, exception_type, exception_message):
    kwargs = _copy_and_update_kwargs("EncryptionMaterials", mod_kwargs)
    materials = EncryptionMaterials(**kwargs)

    with pytest.raises(exception_type) as excinfo:
        materials.add_signing_key(signing_key=signing_key)

    excinfo.match(exception_message)


def test_add_verification_key_success():
    kwargs = _copy_and_update_kwargs("DecryptionMaterials", dict(verification_key=_REMOVE))
    materials = DecryptionMaterials(**kwargs)

    materials.add_verification_key(verification_key=b"")


@pytest.mark.parametrize(
    "mod_kwargs, verification_key, exception_type, exception_message",
    (
        ({}, b"", AttributeError, "Verification key is already set."),
        (
            dict(verification_key=_REMOVE, algorithm=AlgorithmSuite.AES_256_GCM_IV12_TAG16),
            b"",
            SignatureKeyError,
            "Algorithm suite does not support signing keys.",
        ),
    ),
)
def test_add_verification_key_fail(mod_kwargs, verification_key, exception_type, exception_message):
    kwargs = _copy_and_update_kwargs("DecryptionMaterials", mod_kwargs)
    materials = DecryptionMaterials(**kwargs)

    with pytest.raises(exception_type) as excinfo:
        materials.add_verification_key(verification_key=verification_key)

    excinfo.match(exception_message)
