# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import abc
from typing import Any

class CryptoMaterialsManager(abc.ABC):
    @abc.abstractmethod
    def get_encryption_materials(self, request: Any) -> Any: ...
    @abc.abstractmethod
    def decrypt_materials(self, request: Any) -> Any: ...
