# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Deletes the Branch Keys that the examples' tests create.

Ported from ``DeleteBranchKey`` in the AWS Cryptographic Material Providers Library's Dafny test helpers:
``AwsCryptographicMaterialProviders/dafny/AwsCryptographyKeyStore/test/CleanupItems.dfy``
on the ``mutations/mutations`` branch.

Branch Keys SHOULD NOT be deleted in production.
Deleting a Branch Key cryptographically shreds every message it protected;
nothing can decrypt them afterwards.
The examples' tests delete the Branch Keys they create only to keep the shared example table from growing.

Cleanup is best effort, as in the Dafny tests (``var _ := DeleteBranchKey(...)``):
a failure to delete is logged, and never fails the test that created the Branch Keys.
"""
import logging

_LOGGER = logging.getLogger(__name__)

# AWS KMS Key Store item attributes; the table's partition key and sort key.
BRANCH_KEY_IDENTIFIER_FIELD = "branch-key-id"
TYPE_FIELD = "type"
HIERARCHY_VERSION_FIELD = "hierarchy-version"
# Branch Keys created by MPL 1.x are hierarchy version 1, stored as a DynamoDB number.
HIERARCHY_VERSION_VALUE = "1"

# DynamoDB's limit on the actions in one TransactWriteItems request.
MAX_TRANSACT_ITEMS = 100

NOT_BK_ERR_MSG = "A DynamoDB query to gather and delete a Branch Key returned a non-Branch Key item."


def delete_branch_key(ddb_client, table_name, branch_key_id, hierarchy_version=HIERARCHY_VERSION_VALUE):
    """Delete every item of a Branch Key: its active, beacon, and version items.

    As in the Dafny helper, the items are found by querying the Branch Key ID (the partition key),
    filtered to one hierarchy version, then deleted in a single TransactWriteItems request.

    :param ddb_client: boto3 DynamoDB client
    :param str table_name: Name of the DynamoDB table backing the AWS KMS Key Store
    :param str branch_key_id: The Branch Key ID to delete
    :param str hierarchy_version: Only delete items of this hierarchy version
    :returns: True if every item was deleted;
        False if more items remain (more than 100, or more than one page), and this should be called again
    :rtype: bool
    :raises ValueError: if the query returns an item without a sort key, which is not a Branch Key item
    """
    response = ddb_client.query(
        TableName=table_name,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="#hv = :hv",
        ExpressionAttributeNames={"#pk": BRANCH_KEY_IDENTIFIER_FIELD, "#hv": HIERARCHY_VERSION_FIELD},
        ExpressionAttributeValues={":pk": {"S": branch_key_id}, ":hv": {"N": hierarchy_version}},
    )
    items = response.get("Items", [])

    deletes = []
    for item in items:
        if TYPE_FIELD not in item:
            raise ValueError(NOT_BK_ERR_MSG)
        deletes.append(
            {
                "Delete": {
                    "TableName": table_name,
                    "Key": {BRANCH_KEY_IDENTIFIER_FIELD: {"S": branch_key_id}, TYPE_FIELD: item[TYPE_FIELD]},
                }
            }
        )

    if not deletes:
        return True
    ddb_client.transact_write_items(TransactItems=deletes[:MAX_TRANSACT_ITEMS])
    # The Dafny helper only checks the 100 item limit; a query can also return only its first page.
    return len(deletes) <= MAX_TRANSACT_ITEMS and "LastEvaluatedKey" not in response


def cleanup_branch_keys(ddb_client, table_name, branch_key_ids):
    """Delete Branch Keys, best effort: log any failure, never raise.

    :param ddb_client: boto3 DynamoDB client
    :param str table_name: Name of the DynamoDB table backing the AWS KMS Key Store
    :param dict branch_key_ids: Map of tenant (or any label) to Branch Key ID
    :returns: The labels whose Branch Keys may not have been fully deleted
    :rtype: list
    """
    not_deleted = []
    for label, branch_key_id in branch_key_ids.items():
        try:
            if delete_branch_key(ddb_client, table_name, branch_key_id):
                continue
            _LOGGER.warning("Branch Key %s (%s) has items remaining in %s", branch_key_id, label, table_name)
        except Exception:  # pylint: disable=broad-except
            _LOGGER.warning(
                "Failed to delete Branch Key %s (%s) from %s", branch_key_id, label, table_name, exc_info=True
            )
        not_deleted.append(label)
    return not_deleted
