# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Optional
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

class CachingCryptoMaterialsManager(CryptoMaterialsManager):
    def __init__(
        self,
        cache: Any,
        master_key_provider: Optional[Any] = ...,
        backing_materials_manager: Optional[CryptoMaterialsManager] = ...,
        max_age: Optional[float] = ...,
        max_messages_encrypted: Optional[int] = ...,
        max_bytes_encrypted: Optional[int] = ...,
    ) -> None: ...
    def get_encryption_materials(self, request: Any) -> Any: ...
    def decrypt_materials(self, request: Any) -> Any: ...
