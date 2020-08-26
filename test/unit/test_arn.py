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
"""Unit test suite for aws_encryption_sdk.internal.arn functions."""
import pytest

from aws_encryption_sdk.exceptions import MalformedArnError
from aws_encryption_sdk.internal.arn import Arn


class TestArn(object):
    def test_malformed_arn_missing_arn(self):
        arn = "aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            Arn.from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))

    def test_malformed_arn_missing_service(self):
        arn = "aws:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            Arn.from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))

    def test_malformed_arn_missing_region(self):
        arn = "arn:aws:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            Arn.from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))

    def test_malformed_arn_missing_account(self):
        arn = "arn:aws:us-east-1:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            Arn.from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))

    def test_malformed_arn_missing_resource_type(self):
        arn = "arn:aws:us-east-1:222222222222"

        with pytest.raises(MalformedArnError) as excinfo:
            Arn.from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))

    def test_parse_key_arn_success(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        arn = Arn.from_str(arn_str)

        assert arn.partition == "aws"
        assert arn.service == "kms"
        assert arn.region == "us-east-1"
        assert arn.account_id == "222222222222"
        assert arn.resource_type == "key"
        assert arn.resource_id == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

    def test_parse_alias_arn_success(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:alias/aws/service"

        arn = Arn.from_str(arn_str)

        assert arn.partition == "aws"
        assert arn.service == "kms"
        assert arn.region == "us-east-1"
        assert arn.account_id == "222222222222"
        assert arn.resource_type == "alias"
        assert arn.resource_id == "aws/service"
