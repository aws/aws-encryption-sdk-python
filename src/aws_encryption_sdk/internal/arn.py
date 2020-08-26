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


def arn_from_str(arn_str):
    """Parses an input string as an ARN.

    :param str arn_str: The string to parse.
    :returns: An ARN object representing the input string.
    :rtype: aws_encryption_sdk.internal.arn.Arn
    :raises MalformedArnError: if the string cannot be parsed as an ARN.
    """
    elements = arn_str.split(":", 5)

    if elements[0] != "arn":
        raise MalformedArnError("Resource {} could not be parsed as an ARN".format(arn_str))

    try:
        partition = elements[1]
        service = elements[2]
        region = elements[3]
        account = elements[4]

        resource = elements[5]
        resource_elements = resource.split("/", 1)
        resource_type = resource_elements[0]
        resource_id = resource_elements[1]

        return Arn(partition, service, region, account, resource_type, resource_id)
    except IndexError:
        raise MalformedArnError("Resource {} could not be parsed as an ARN".format(arn_str))
