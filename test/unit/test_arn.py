# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.internal.arn functions."""
import pytest

from aws_encryption_sdk.exceptions import MalformedArnError
from aws_encryption_sdk.internal.arn import arn_from_str, is_valid_mrk_arn_str, is_valid_mrk_identifier

pytestmark = [pytest.mark.unit, pytest.mark.local]

VALID_KMS_ARNS = [
    "arn:aws:kms:us-west-2:123456789012:key/12345678",
    "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678",
    "arn:aws:kms:us-west-2:123456789012:alias/myAlias",
]

VALID_KMS_IDENTIFIERS = [
    "alias/myAlias",
    "12345678",
    "mrk-12345678",
] + VALID_KMS_ARNS

INVALID_KMS_IDENTIFIERS = [
    "arn::kms:us-west-2:123456789012:key/12345678",
    "arn:aws:not-kms:us-west-2:123456789012:key/12345678",
    "arn:aws:kms::123456789012:key/12345678",
    "arn:aws:kms:us-west-2::key/12345678",
    "arn:aws:kms:us-west-2:123456789012:",
    "arn:aws:kms:us-west-2:123456789012:key/",
    "arn:aws:kms:us-west-2:123456789012:alias/",
    "arn:aws:kms:us-west-2:123456789012:/12345678",
    "arn:aws:kms:us-west-2:123456789012:key:12345678",
    "arn:aws:kms:us-west-2:123456789012:alias:myAlias",
]

INVALID_KMS_ARNS = [
    ":aws:kms:us-west-2:123456789012:key/12345678",
] + INVALID_KMS_IDENTIFIERS


class TestArn(object):
    def test_malformed_arn_missing_arn(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# MUST start with string "arn"
        arn = ":aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Missing 'arn' string")

    def test_parse_key_arn_missing_partition(self):
        arn = "arn::kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The partition MUST be a non-empty

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Missing partition")

    def test_malformed_arn_service_not_kms(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The service MUST be the string "kms"
        arn = "arn:aws:notkms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Unknown service")

    def test_malformed_arn_missing_region(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The region MUST be a non-empty string
        arn = "arn:aws:kms::222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Missing region")

    def test_malformed_arn_missing_account(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The account MUST be a non-empty string
        arn = "arn:aws:kms:us-east-1::key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Missing account")

    def test_malformed_arn_missing_resource_type(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The resource section MUST be non-empty and MUST be split by a
        # //# single "/" any additional "/" are included in the resource id
        arn = "arn:aws:kms:us-east-1:222222222222:"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Missing resource")

    def test_malformed_arn_unknown_resource_type(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The resource type MUST be either "alias" or "key"
        arn = "arn:aws:kms:us-east-1:222222222222:s3bucket/foo"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Unknown resource type")

    def test_malformed_arn_missing_resource_id(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
        # //= type=test
        # //# The resource id MUST be a non-empty string
        arn = "arn:aws:kms:us-east-1:222222222222:key/"

        with pytest.raises(MalformedArnError) as excinfo:
            arn_from_str(arn)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn))
        excinfo.match("Missing resource id")

    def test_parse_key_arn_success(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

        arn = arn_from_str(arn_str)

        assert arn.partition == "aws"
        assert arn.service == "kms"
        assert arn.region == "us-east-1"
        assert arn.account_id == "222222222222"
        assert arn.resource_type == "key"
        assert arn.resource_id == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

    def test_parse_alias_arn_success(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:alias/aws/service"

        arn = arn_from_str(arn_str)

        assert arn.partition == "aws"
        assert arn.service == "kms"
        assert arn.region == "us-east-1"
        assert arn.account_id == "222222222222"
        assert arn.resource_type == "alias"
        assert arn.resource_id == "aws/service"

    def test_arn_round_trip_key_id(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:key/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
        arn = arn_from_str(arn_str)
        arn_str_2 = arn.to_string()

        assert arn_str == arn_str_2

    def test_arn_round_trip_alias(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:alias/aws/service"
        arn = arn_from_str(arn_str)
        arn_str_2 = arn.to_string()

        assert arn_str == arn_str_2

    def test_mrk_arn_is_valid_mrk(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:key/mrk-1234-5678-9012-34567890"

        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //= type=test
        # //# This function MUST take a single AWS KMS ARN

        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //= type=test
        # //# If resource type is "key" and resource ID starts with
        # //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
        assert is_valid_mrk_arn_str(arn_str)

    def test_non_mrk_arn_is_not_valid_mrk(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //= type=test
        # //# If resource type is "key" and resource ID does not start with "mrk-",
        # //# this is a (single-region) AWS KMS key ARN and MUST return false.
        arn_str = "arn:aws:kms:us-east-1:222222222222:key/1234-5678-9012-34567890"

        assert not is_valid_mrk_arn_str(arn_str)

    def test_alias_arn_is_not_valid_mrk(self):
        arn_str = "arn:aws:kms:us-east-1:222222222222:alias/mrk-1234-5678-9012-34567890"
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //= type=test
        # //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
        # //# return false.
        assert not is_valid_mrk_arn_str(arn_str)

    @pytest.mark.parametrize(
        "key_id",
        INVALID_KMS_ARNS,
    )
    def test_is_valid_mrk_arn_str_throw_on_invalid_arn(self, key_id):
        with pytest.raises(MalformedArnError) as excinfo:
            is_valid_mrk_arn_str(key_id)
        excinfo.match("Resource {} could not be parsed as an ARN".format(key_id))

    def test_is_valid_mrk_arn_str_throw_on_bare_id(self):
        arn_str = "mrk-1234-5678-9012-34567890"

        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //= type=test
        # //# If the input is an invalid AWS KMS ARN this function MUST error.
        with pytest.raises(MalformedArnError) as excinfo:
            is_valid_mrk_arn_str(arn_str)
        excinfo.match("Resource {} could not be parsed as an ARN".format(arn_str))
        excinfo.match("Missing 'arn' string")

    def test_mrk_arn_is_valid_mrk_identifier(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //= type=test
        # //# This function MUST take a single AWS KMS identifier

        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //= type=test
        # //# If the input starts with "arn:", this MUST return the output of
        # //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
        # //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
        # //# input.
        id_str = "arn:aws:kms:us-east-1:222222222222:key/mrk-1234-5678-9012-34567890"
        assert is_valid_mrk_identifier(id_str)

    def test_bare_mrk_id_is_valid_mrk_identifier(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //= type=test
        # //# If the input starts with "mrk-", this is a multi-Region key id and
        # //# MUST return true.
        id_str = "mrk-1234-5678-9012-34567890"
        assert is_valid_mrk_identifier(id_str)

    def test_alias_arn_is_not_valid_mrk_identifier(self):
        id_str = "arn:aws:kms:us-east-1:222222222222:alias/myAlias"
        assert not is_valid_mrk_identifier(id_str)

    def test_bare_alias_is_not_valid_mrk_identifier(self):
        id_str = "alias/myAlias"
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //= type=test
        # //# If the input starts with "alias/", this an AWS KMS alias and not a
        # //# multi-Region key id and MUST return false.
        assert not is_valid_mrk_identifier(id_str)

    def test_bare_srk_id_is_not_valid_mrk_identifier(self):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //= type=test
        # //# If
        # //# the input does not start with any of the above, this is a multi-
        # //# Region key id and MUST return false.
        id_str = "1234-5678-9012-34567890"
        assert not is_valid_mrk_identifier(id_str)

    def test_srk_arn_is_not_valid_mrk_identifier(self):
        id_str = "arn:aws:kms:us-east-1:222222222222:key/1234-5678-9012-34567890"
        assert not is_valid_mrk_identifier(id_str)

    @pytest.mark.parametrize(
        "key_id",
        INVALID_KMS_ARNS,
    )
    def test_is_not_valid_mrk_identifier_throws_on_invalid_arn(self, key_id):
        with pytest.raises(MalformedArnError) as excinfo:
            is_valid_mrk_arn_str(key_id)
        excinfo.match("Resource {} could not be parsed as an ARN".format(key_id))
