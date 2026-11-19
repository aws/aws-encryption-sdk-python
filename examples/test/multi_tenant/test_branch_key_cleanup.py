# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the Branch Key cleanup test helper."""
# pylint: disable=redefined-outer-name
import boto3
import pytest
from botocore.stub import Stubber

from ..branch_key_cleanup import cleanup_branch_keys, delete_branch_key

pytestmark = [pytest.mark.examples]

TABLE = "KeyStoreDdbTable"
BKID = "bbb9baf1-03e6-4716-a586-6bf29995314b"
QUERY = {
    "TableName": TABLE,
    "KeyConditionExpression": "#pk = :pk",
    "FilterExpression": "#hv = :hv",
    "ExpressionAttributeNames": {"#pk": "branch-key-id", "#hv": "hierarchy-version"},
    "ExpressionAttributeValues": {":pk": {"S": BKID}, ":hv": {"N": "1"}},
}


def _item(type_value):
    return {"branch-key-id": {"S": BKID}, "type": {"S": type_value}, "hierarchy-version": {"N": "1"}}


def _delete(type_value):
    return {"Delete": {"TableName": TABLE, "Key": {"branch-key-id": {"S": BKID}, "type": {"S": type_value}}}}


@pytest.fixture
def ddb():
    client = boto3.client(
        "dynamodb", region_name="us-west-2", aws_access_key_id="AKIAFAKE", aws_secret_access_key="fake"
    )
    with Stubber(client) as stubber:
        yield client, stubber
        stubber.assert_no_pending_responses()


def test_deletes_active_beacon_and_versions_in_one_transaction(ddb):
    client, stubber = ddb
    types = ["branch:ACTIVE", "beacon:ACTIVE", "branch:version:83eec007-5659-4554-bf11-699b90f41ac6"]
    stubber.add_response("query", {"Items": [_item(t) for t in types]}, QUERY)
    stubber.add_response("transact_write_items", {}, {"TransactItems": [_delete(t) for t in types]})
    assert delete_branch_key(client, TABLE, BKID) is True


def test_nothing_to_delete(ddb):
    client, stubber = ddb
    stubber.add_response("query", {"Items": []}, QUERY)
    assert delete_branch_key(client, TABLE, BKID) is True


def test_more_than_100_items_deletes_100_and_reports_more_remain(ddb):
    client, stubber = ddb
    types = ["branch:version:{}".format(i) for i in range(101)]
    stubber.add_response("query", {"Items": [_item(t) for t in types]}, QUERY)
    stubber.add_response("transact_write_items", {}, {"TransactItems": [_delete(t) for t in types[:100]]})
    assert delete_branch_key(client, TABLE, BKID) is False


def test_more_pages_reports_more_remain(ddb):
    client, stubber = ddb
    stubber.add_response(
        "query", {"Items": [_item("branch:ACTIVE")], "LastEvaluatedKey": _item("branch:ACTIVE")}, QUERY
    )
    stubber.add_response("transact_write_items", {}, {"TransactItems": [_delete("branch:ACTIVE")]})
    assert delete_branch_key(client, TABLE, BKID) is False


def test_refuses_items_without_a_sort_key(ddb):
    client, stubber = ddb
    stubber.add_response("query", {"Items": [{"branch-key-id": {"S": BKID}}]}, QUERY)
    with pytest.raises(ValueError):
        delete_branch_key(client, TABLE, BKID)


def test_cleanup_is_best_effort(ddb):
    client, stubber = ddb
    stubber.add_client_error("query", service_error_code="AccessDeniedException", http_status_code=400)
    stubber.add_response("query", {"Items": []})
    # The first Branch Key's cleanup fails; it is reported, not raised, and the second is still attempted.
    assert cleanup_branch_keys(client, TABLE, {"TenantA": BKID, "TenantB": BKID}) == ["TenantA"]
