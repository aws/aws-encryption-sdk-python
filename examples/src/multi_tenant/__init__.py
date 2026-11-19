# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Call AWS KMS with per-tenant credentials over one shared connection pool.

See design.md in this directory for the options considered and the decisions made.
"""
from .kms_transport import KmsTransport
from .tenant_kms_client import TenantKmsClient

__all__ = ("KmsTransport", "TenantKmsClient")
