# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions to handle configuration and credentials setup for functional tests."""
import boto3
import pytest
from moto.kms import mock_kms

FAKE_REGION = "us-west-2"


def _create_cmk():
    # type: () -> str
    kms = boto3.client("kms", region_name=FAKE_REGION)
    response = kms.create_key()
    return response["KeyMetadata"]["Arn"]


@pytest.fixture
def fake_generator():
    with mock_kms():
        yield _create_cmk()


@pytest.fixture
def fake_generator_and_child():
    with mock_kms():
        generator = _create_cmk()
        child = _create_cmk()
        yield generator, child
