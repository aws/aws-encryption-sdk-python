# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper utilities for use by integration tests."""
import base64
import json
import os
from collections import namedtuple
from typing import Any, Callable, Iterable, Optional, Text

import aws_encryption_sdk
import pytest
from aws_encryption_sdk.identifiers import CommitmentPolicy
from aws_encryption_sdk.key_providers.kms import StrictAwsKmsMasterKeyProvider

HERE = os.path.abspath(os.path.dirname(__file__))
DEPLOYMENT_REGION = "AWS_ENCRYPTION_SDK_PYTHON_DECRYPT_ORACLE_REGION"
DEPLOYMENT_ID = "AWS_ENCRYPTION_SDK_PYTHON_DECRYPT_ORACLE_API_DEPLOYMENT_ID"
AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"
_KMS_MKP = None
_ENDPOINT = None

CLIENT = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)


def decrypt_endpoint() -> Text:
    """Build the API endpoint based on environment variables."""
    global _ENDPOINT  # pylint: disable=global-statement

    if _ENDPOINT is not None:
        return _ENDPOINT

    try:
        deployment_id = os.environ[DEPLOYMENT_ID]
        region = os.environ[DEPLOYMENT_REGION]
    except KeyError as error:
        raise ValueError(
            (
                'Environment variables "{region}" and "{deployment}" '
                "must be set to the correct values for the deployed decrypt oracle."
            ).format(region=DEPLOYMENT_REGION, deployment=DEPLOYMENT_ID)
        ) from error

    _ENDPOINT = "https://{deployment_id}.execute-api.{region}.amazonaws.com/api/v0/decrypt".format(
        deployment_id=deployment_id, region=region
    )
    return _ENDPOINT


def get_cmk_arn() -> Text:
    """Retrieve the target CMK ARN from environment variable."""
    try:
        arn = os.environ[AWS_KMS_KEY_ID]
    except KeyError as error:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID
            )
        ) from error

    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn

    raise ValueError("KMS CMK ARN provided for integration tests must be a key not an alias")


def kms_master_key_provider(cache: Optional[bool] = True):
    """Build the expected KMS Master Key Provider based on environment variables."""
    global _KMS_MKP  # pylint: disable=global-statement

    if cache and _KMS_MKP is not None:
        return _KMS_MKP

    cmk_arn = get_cmk_arn()
    _kms_master_key_provider = StrictAwsKmsMasterKeyProvider(key_ids=[cmk_arn])

    if cache:
        _KMS_MKP = _kms_master_key_provider

    return _kms_master_key_provider


def test_vectors_filename() -> Text:
    """Provide the absolute path to the test vectors file."""
    return os.path.join(HERE, "..", "vectors", "decrypt_vectors.json")


TestVector = namedtuple("TestVector", ["plaintext", "ciphertext", "key_type", "algorithm_suite"])


def all_test_vectors() -> Iterable[Any]:
    """Collect and iterate through all test vectors."""

    with open(test_vectors_filename(), "r", encoding="utf-8") as vectors_file:
        raw_vectors = json.load(vectors_file)

    for vector in raw_vectors:
        vector_name = "::".join([vector["key-type"], vector["algorithm-suite"]])
        plaintext = base64.b64decode(vector["plaintext"].encode("utf-8"))
        ciphertext = base64.b64decode(vector["ciphertext"].encode("utf-8"))
        yield pytest.param(
            TestVector(
                plaintext=plaintext,
                ciphertext=ciphertext,
                key_type=vector["key-type"],
                algorithm_suite=vector["algorithm-suite"],
            ),
            id=vector_name,
        )


def filtered_test_vectors(filter_function: Callable) -> Iterable[Any]:
    """Collect and iterate through all test vectors that pass the filter function."""
    for vector_param in all_test_vectors():
        if filter_function(vector_param.values[0]):
            yield vector_param
