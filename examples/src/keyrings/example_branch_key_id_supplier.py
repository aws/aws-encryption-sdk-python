from aws_cryptographic_materialproviders.mpl.models import GetBranchKeyIdInput, GetBranchKeyIdOutput
from aws_cryptographic_materialproviders.mpl.references import IBranchKeyIdSupplier
from typing import Dict


class ExampleBranchKeyIdSupplier(IBranchKeyIdSupplier):
    """Example implementation of a branch key ID supplier."""

    branch_key_id_for_tenant_A: str
    branch_key_id_for_tenant_B: str

    def __init__(self, tenant_1_id, tenant_2_id):
        self.branch_key_id_for_tenant_A = tenant_1_id
        self.branch_key_id_for_tenant_B = tenant_2_id

    def get_branch_key_id(
        self,
        # Change this to `native_input`
        input: GetBranchKeyIdInput  # noqa pylint: disable=redefined-builtin
    ) -> GetBranchKeyIdOutput:
        """Returns branch key ID from the tenant ID in input's encryption context."""
        encryption_context: Dict[str, str] = input.encryption_context

        if b"tenant" not in encryption_context:
            raise ValueError("EncryptionContext invalid, does not contain expected tenant key value pair.")

        tenant_key_id: str = encryption_context.get(b"tenant")
        branch_key_id: str

        if tenant_key_id == b"TenantA":
            branch_key_id = self.branch_key_id_for_tenant_A
        elif tenant_key_id == b"TenantB":
            branch_key_id = self.branch_key_id_for_tenant_B
        else:
            raise ValueError(f"Item does not contain valid tenant ID: {tenant_key_id=}")

        return GetBranchKeyIdOutput(branch_key_id=branch_key_id)