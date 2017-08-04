"""Unit test suite for aws_encryption_sdk.structures"""
import attr
from mock import MagicMock
import pytest
import six

from aws_encryption_sdk.identifiers import (
    SerializationVersion, ObjectType, Algorithm, ContentType
)
from aws_encryption_sdk.internal.str_ops import to_str, to_bytes
from aws_encryption_sdk.structures import (
    MessageHeader, MasterKeyInfo, RawDataKey, DataKey, EncryptedDataKey
)


@pytest.mark.parametrize('attribute, validator_type, convert_function', (
    (MessageHeader.version, SerializationVersion, None),
    (MessageHeader.type, ObjectType, None),
    (MessageHeader.algorithm, Algorithm, None),
    (MessageHeader.message_id, bytes, None),
    (MessageHeader.encryption_context, dict, None),
    (MessageHeader.encrypted_data_keys, set, None),
    (MessageHeader.content_type, ContentType, None),
    (MessageHeader.content_aad_length, six.integer_types, None),
    (MessageHeader.header_iv_length, six.integer_types, None),
    (MessageHeader.frame_length, six.integer_types, None),
    (MasterKeyInfo.provider_id, (six.string_types, bytes), to_str),
    (MasterKeyInfo.key_info, (six.string_types, bytes), to_bytes),
    (RawDataKey.key_provider, MasterKeyInfo, None),
    (RawDataKey.data_key, bytes, None),
    (DataKey.key_provider, MasterKeyInfo, None),
    (DataKey.data_key, bytes, None),
    (DataKey.encrypted_data_key, bytes, None),
    (EncryptedDataKey.key_provider, MasterKeyInfo, None),
    (EncryptedDataKey.encrypted_data_key, bytes, None)
))
def test_attributes(attribute, validator_type, convert_function):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.validator.type == validator_type
    assert attribute.hash
    if convert_function is not None:
        assert attribute.convert is convert_function


@pytest.mark.parametrize(
    (
        'version,'
        'message_type,'
        'algorithm,'
        'message_id,'
        'encryption_context,'
        'encrypted_data_keys,'
        'content_type,'
        'content_aad_length,'
        'header_iv_length,'
        'frame_length'
    ),
    (
        (
            None,
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            {},
            set([]),
            MagicMock(__class__=ContentType),
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            None,
            MagicMock(__class__=Algorithm),
            b'',
            {},
            set([]),
            MagicMock(__class__=ContentType),
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            None,
            b'',
            {},
            set([]),
            MagicMock(__class__=ContentType),
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            None,
            {},
            set([]),
            MagicMock(__class__=ContentType),
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            None,
            set([]),
            MagicMock(__class__=ContentType),
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            {},
            None,
            MagicMock(__class__=ContentType),
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            {},
            set([]),
            None,
            5,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            {},
            set([]),
            MagicMock(__class__=ContentType),
            None,
            5,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            {},
            set([]),
            MagicMock(__class__=ContentType),
            5,
            None,
            5
        ),
        (
            MagicMock(__class__=SerializationVersion),
            MagicMock(__class__=ObjectType),
            MagicMock(__class__=Algorithm),
            b'',
            {},
            set([]),
            MagicMock(__class__=ContentType),
            5,
            5,
            None
        )
    )
)
def test_message_header_attributes_fails(
    version,
    message_type,
    algorithm,
    message_id,
    encryption_context,
    encrypted_data_keys,
    content_type,
    content_aad_length,
    header_iv_length,
    frame_length
):
    with pytest.raises(TypeError):
        MessageHeader(
            version=version,
            type=message_type,
            algorithm=algorithm,
            message_id=message_id,
            encryption_context=encryption_context,
            encrypted_data_keys=encrypted_data_keys,
            content_type=content_type,
            content_aad_length=content_aad_length,
            header_iv_length=header_iv_length,
            frame_length=frame_length
        )


def test_message_header_attributes_succeeds():
    MessageHeader(
        version=MagicMock(__class__=SerializationVersion),
        type=MagicMock(__class__=ObjectType),
        algorithm=MagicMock(__class__=Algorithm),
        message_id=b'',
        encryption_context={},
        encrypted_data_keys=set([]),
        content_type=MagicMock(__class__=ContentType),
        content_aad_length=5,
        header_iv_length=5,
        frame_length=5
    )


@pytest.mark.parametrize('provider_id, key_info', (
    (None, 'key'),
    ('provider', None)
))
def test_master_key_info_attributes_fails(provider_id, key_info):
    with pytest.raises(TypeError):
        MasterKeyInfo(provider_id=provider_id, key_info=key_info)


@pytest.mark.parametrize('provider_id, key_info', (
    ('provider', 'key'),
    (b'provider', b'key')
))
def test_key_info_attributes_converts(provider_id, key_info):
    test = MasterKeyInfo(
        provider_id=provider_id,
        key_info=key_info
    )
    assert test.provider_id == 'provider'
    assert test.key_info == b'key'


@pytest.mark.parametrize('key_provider, data_key', (
    (None, b''),
    (MagicMock(__class__=MasterKeyInfo), None)
))
def test_raw_data_key_attributes_fails(key_provider, data_key):
    with pytest.raises(TypeError):
        RawDataKey(
            key_provider=key_provider,
            data_key=data_key
        )


def test_raw_data_key_attributes_succeeds():
    RawDataKey(
        key_provider=MagicMock(__class__=MasterKeyInfo),
        data_key=b''
    )


@pytest.mark.parametrize('key_provider, data_key, encrypted_data_key', (
    (None, b'', b''),
    (MagicMock(__class__=MasterKeyInfo), None, b''),
    (MagicMock(__class__=MasterKeyInfo), b'', None)
))
def test_data_key_attributes_fails(key_provider, data_key, encrypted_data_key):
    with pytest.raises(TypeError):
        DataKey(
            key_provider=key_provider,
            data_key=data_key,
            encryted_data_key=encrypted_data_key
        )


def test_data_key_attributes_succeeds():
    DataKey(
        key_provider=MagicMock(__class__=MasterKeyInfo),
        data_key=b'',
        encrypted_data_key=b''
    )


@pytest.mark.parametrize('key_provider, encrypted_data_key', (
    (None, b''),
    (MagicMock(__class__=MasterKeyInfo), None)
))
def test_encrypted_data_key_attributes_fails(key_provider, encrypted_data_key):
    with pytest.raises(TypeError):
        EncryptedDataKey(
            key_provider=key_provider,
            encryted_data_key=encrypted_data_key
        )


def test_Encrypted_data_key_attributes_succeeds():
    EncryptedDataKey(
        key_provider=MagicMock(__class__=MasterKeyInfo),
        encrypted_data_key=b''
    )
