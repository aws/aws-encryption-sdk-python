# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.internal.structures"""
import pytest

from aws_encryption_sdk.internal.structures import (
    EncryptedData,
    MessageFooter,
    MessageFrameBody,
    MessageHeaderAuthentication,
    MessageNoFrameBody,
)

from .unit_test_utils import all_invalid_kwargs, all_valid_kwargs

pytestmark = [pytest.mark.unit, pytest.mark.local]


VALID_KWARGS = {
    EncryptedData: [
        dict(ciphertext=b"asjfoiwaj", iv=None, tag=None),
        dict(ciphertext=b"asjfoiwaj", iv=b"ajsdhfiuaweh", tag=None),
        dict(ciphertext=b"asjfoiwaj", iv=None, tag=b"aosijfoiewj"),
        dict(ciphertext=b"asjfoiwaj", iv=b"ajsdhfiuaweh", tag=b"aosijfoiewj"),
    ],
    MessageHeaderAuthentication: [dict(iv=b"oasijfoaiwej", tag=b"aisudhfoaweij")],
    MessageFrameBody: [
        dict(
            iv=b"oaijefoiajew",
            ciphertext=b"oasidjfaowiejf",
            tag=b"ecoaiwjeconadf",
            sequence_number=42523,
            final_frame=False,
        )
    ],
    MessageNoFrameBody: [dict(iv=b"afioaewj", ciphertext=b"oasjfoeiwjfio", tag=b"asfowaeijf")],
    MessageFooter: [dict(signature=b"oajwefiowjaeofi")],
}
INVALID_KWARGS = {EncryptedData: [dict(ciphertext=None, iv=None, tag=None)]}


@pytest.mark.parametrize("cls, kwargs", all_valid_kwargs(VALID_KWARGS))
def test_attributes_valid_kwargs(cls, kwargs):
    cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", all_invalid_kwargs(VALID_KWARGS, INVALID_KWARGS))
def test_attributes_invalid_kwargs(cls, kwargs):
    with pytest.raises(TypeError):
        cls(**kwargs)


@pytest.mark.parametrize(
    "attribute, value", ((MessageNoFrameBody.sequence_number, 1), (MessageNoFrameBody.final_frame, True))
)
def test_static_attributes(attribute, value):
    assert attribute == value
