# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example implementation of a branch key ID supplier."""

from aws_cryptographic_material_providers.mpl.models import GetBranchKeyIdInput, GetBranchKeyIdOutput
from aws_cryptographic_material_providers.mpl.references import IBranchKeyIdSupplier
from typing import Dict  # noqa pylint: disable=wrong-import-order


class ExampleBranchKeyIdSupplier(IBranchKeyIdSupplier):
    """Example implementation of a branch key ID supplier."""

    branch_key_id_for_tenant_A: str
    branch_key_id_for_tenant_B: str

    def __init__(self, tenant_1_id, tenant_2_id):
        """Example constructor for a branch key ID supplier."""
        self.branch_key_id_for_tenant_A = tenant_1_id
        self.branch_key_id_for_tenant_B = tenant_2_id

    def get_branch_key_id(
        self,
        param: GetBranchKeyIdInput
    ) -> GetBranchKeyIdOutput:
        """Returns branch key ID from the tenant ID in input's encryption context."""
        encryption_context: Dict[str, str] = param.encryption_context

        if "tenant" not in encryption_context:
            raise ValueError("EncryptionContext invalid, does not contain expected tenant key value pair.")

        tenant_key_id: str = encryption_context.get("tenant")
        branch_key_id: str

        if tenant_key_id == "TenantA":
            branch_key_id = self.branch_key_id_for_tenant_A
        elif tenant_key_id == "TenantB":
            branch_key_id = self.branch_key_id_for_tenant_B
        else:
            raise ValueError(f"Item does not contain valid tenant ID: {tenant_key_id=}")

        return GetBranchKeyIdOutput(branch_key_id=branch_key_id)
