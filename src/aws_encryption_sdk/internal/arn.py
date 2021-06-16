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
"""Utility class for processing Amazon Resource Names (ARNs)"""

from aws_encryption_sdk.exceptions import MalformedArnError


class Arn(object):
    """Arn to identify AWS resources. See https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
        for details.

    :param str partition: The AWS partition of the resource, e.g. 'aws'
    :param str service: The service of the resource, e.g. 'kms'
    :param str region: The region to which the resource belongs, e.g. 'us-east-1'
    :param str account_id: The account containing the resource, e.g. '123456789012'
    :param str resource_type: The type of the resource, e.g. 'key'
    :param resource_id: The id for the resource, e.g. 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb'
    """

    def __init__(self, partition, service, region, account_id, resource_type, resource_id):
        """Initializes an ARN with all required fields."""
        self.partition = partition
        self.service = service
        self.region = region
        self.account_id = account_id
        self.resource_type = resource_type
        self.resource_id = resource_id

    def to_string(self):
        """Returns the string format of the ARN."""
        return ":".join(
            [
                "arn",
                self.partition,
                self.service,
                self.region,
                self.account_id,
                "/".join([self.resource_type, self.resource_id]),
            ]
        )

    def indicates_multi_region_key(self):
        """Returns True if this ARN indicates a multi-region key, otherwise False"""
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
        # //# return false.

        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //# If resource type is "key" and resource ID does not start with "mrk-",
        # //# this is a (single-region) AWS KMS key ARN and MUST return false.

        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
        # //# If resource type is "key" and resource ID starts with
        # //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.

        return self.resource_type == "key" and self.resource_id.startswith("mrk-")


def is_valid_mrk_arn_str(arn_str):
    """Determines whether a string can be interpreted as
    a valid MRK ARN

    :param str arn_str: The string to parse.
    :returns: a bool representing whether this key ARN indicates an MRK
    :rtype: bool
    :raises MalformedArnError: if the string fails to parse as an ARN
    """
    # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    # //# This function MUST take a single AWS KMS ARN

    # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
    # //# If the input is an invalid AWS KMS ARN this function MUST error.
    arn = arn_from_str(arn_str)
    return arn.indicates_multi_region_key()


def is_valid_mrk_identifier(id_str):
    """Determines whether a string can be interpreted as
    a valid MRK identifier; either an MRK arn or a raw resource ID for an MRK.

    :param str id_str: The string to parse.
    :returns: a bool representing whether this key identifier indicates an MRK
    :rtype: bool
    :raises MalformedArnError: if the string starts with "arn:" but fails to parse as an ARN
    """
    # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    # //# This function MUST take a single AWS KMS identifier

    if id_str.startswith("arn:"):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //# If the input starts with "arn:", this MUST return the output of
        # //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
        # //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
        # //# input.
        return is_valid_mrk_arn_str(id_str)
    elif id_str.startswith("alias/"):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //# If the input starts with "alias/", this an AWS KMS alias and not a
        # //# multi-Region key id and MUST return false.
        return False
    elif id_str.startswith("mrk-"):
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //# If the input starts with "mrk-", this is a multi-Region key id and
        # //# MUST return true.
        return True
    else:
        # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
        # //# If
        # //# the input does not start with any of the above, this is a multi-
        # //# Region key id and MUST return false.
        return False


def arn_from_str(arn_str):  # noqa: C901
    """Parses an input string as an ARN.

    :param str arn_str: The string to parse.
    :returns: An ARN object representing the input string.
    :rtype: aws_encryption_sdk.internal.arn.Arn
    :raises MalformedArnError: if the string cannot be parsed as an ARN.
    """
    elements = arn_str.split(":", 5)

    try:
        if elements[0] != "arn":
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# MUST start with string "arn"
            raise MalformedArnError("Missing 'arn' string")

        partition = elements[1]
        service = elements[2]
        region = elements[3]
        account = elements[4]

        if not partition:
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The partition MUST be a non-empty
            raise MalformedArnError("Missing partition")

        if not account:
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The account MUST be a non-empty string
            raise MalformedArnError("Missing account")

        if not region:
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The region MUST be a non-empty string
            raise MalformedArnError("Missing region")

        if service != "kms":
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The service MUST be the string "kms"
            raise MalformedArnError("Unknown service")

        resource = elements[5]
        if not resource:
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The resource section MUST be non-empty and MUST be split by a
            # //# single "/" any additional "/" are included in the resource id
            raise MalformedArnError("Missing resource")

        resource_elements = resource.split("/", 1)
        resource_type = resource_elements[0]
        resource_id = resource_elements[1]

        if resource_type not in ("alias", "key"):
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The resource type MUST be either "alias" or "key"
            raise MalformedArnError("Unknown resource type")

        if not resource_id:
            # //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
            # //# The resource id MUST be a non-empty string
            raise MalformedArnError("Missing resource id")

        return Arn(partition, service, region, account, resource_type, resource_id)
    except (IndexError, MalformedArnError) as exc:
        raise MalformedArnError("Resource {} could not be parsed as an ARN: {}".format(arn_str, exc.args[0]))
