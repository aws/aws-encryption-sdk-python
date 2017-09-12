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
"""Unit test suite for aws_encryption_sdk.internal.structures"""
import attr
import pytest
import six

from aws_encryption_sdk.internal.structures import (
    EncryptedData, MessageFooter, MessageFrameBody, MessageHeaderAuthentication, MessageNoFrameBody
)


@pytest.mark.parametrize('attribute, validator_type, is_optional', (
    (EncryptedData.iv, bytes, True),
    (EncryptedData.ciphertext, bytes, False),
    (EncryptedData.tag, bytes, True),
    (MessageHeaderAuthentication.iv, bytes, False),
    (MessageHeaderAuthentication.tag, bytes, False),
    (MessageFrameBody.iv, bytes, False),
    (MessageFrameBody.ciphertext, bytes, False),
    (MessageFrameBody.tag, bytes, False),
    (MessageFrameBody.sequence_number, six.integer_types, False),
    (MessageFrameBody.final_frame, bool, False),
    (MessageNoFrameBody.iv, bytes, False),
    (MessageNoFrameBody.ciphertext, bytes, False),
    (MessageNoFrameBody.tag, bytes, False),
    (MessageFooter.signature, bytes, False)
))
def test_attributes(attribute, validator_type, is_optional):
    assert isinstance(attribute, attr.Attribute)
    assert attribute.hash
    if is_optional:
        assert attribute.validator.validator.type == validator_type
    else:
        assert attribute.validator.type == validator_type


@pytest.mark.parametrize('attribute, value', (
    (MessageNoFrameBody.sequence_number, 1),
    (MessageNoFrameBody.final_frame, True)
))
def test_static_attributes(attribute, value):
    assert attribute == value


def test_encrypted_data_fails():
    with pytest.raises(TypeError):
        EncryptedData(ciphertext=None)


@pytest.mark.parametrize('iv, ciphertext, tag', (
    (b'iv', b'ciphertext', b'tag'),
    (None, b'ciphertext', None)
))
def test_encrypted_data_succeeds(iv, ciphertext, tag):
    EncryptedData(iv=iv, ciphertext=ciphertext, tag=tag)


@pytest.mark.parametrize('iv, tag', (
    (None, b''),
    (b'', None)
))
def test_message_header_auth_fails(iv, tag):
    with pytest.raises(TypeError):
        MessageHeaderAuthentication(iv=iv, tag=tag)


def test_message_header_auth_succeeds():
    MessageHeaderAuthentication(iv=b'', tag=b'')


@pytest.mark.parametrize('iv, ciphertext, tag, sequence_number, final_frame', (
    (None, b'', b'', 1, True),
    (b'', None, b'', 1, True),
    (b'', b'', None, 1, True),
    (b'', b'', b'', None, True),
    (b'', b'', b'', 1, None)
))
def test_message_frame_body_fails(iv, ciphertext, tag, sequence_number, final_frame):
    with pytest.raises(TypeError):
        MessageFrameBody(
            iv=iv,
            ciphertext=ciphertext,
            tag=tag,
            sequence_number=sequence_number,
            final_frame=final_frame
        )


def test_message_frame_body_succeeds():
    MessageFrameBody(
        iv=b'iv',
        ciphertext=b'ciphertext',
        tag=b'tag',
        sequence_number=1,
        final_frame=False
    )


@pytest.mark.parametrize('iv, ciphertext, tag', (
    (None, b'', b''),
    (b'', None, b''),
    (b'', b'', None)
))
def test_message_no_frame_body_fails(iv, ciphertext, tag):
    with pytest.raises(TypeError):
        MessageNoFrameBody(iv=iv, ciphertext=ciphertext, tag=tag)


def test_message_no_frame_body_succeeds():
    test = MessageNoFrameBody(iv=b'', ciphertext=b'', tag=b'')
    assert test.sequence_number == 1
    assert test.final_frame


def test_message_footer_fails():
    with pytest.raises(TypeError):
        MessageFooter(signature=None)


def test_message_footer_succeeds():
    MessageFooter(signature=b'')
