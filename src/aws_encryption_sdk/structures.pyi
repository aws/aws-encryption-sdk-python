# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict, Optional, Set
from aws_encryption_sdk.identifiers import (
    Algorithm,
    ContentType,
    ObjectType,
    SerializationVersion,
)

class MasterKeyInfo:
    provider_id: str
    key_info: bytes
    def __init__(self, provider_id: str, key_info: bytes) -> None: ...

class RawDataKey:
    key_provider: MasterKeyInfo
    data_key: bytes
    def __init__(self, key_provider: MasterKeyInfo, data_key: bytes) -> None: ...

class DataKey(RawDataKey):
    encrypted_data_key: bytes
    def __init__(
        self, key_provider: MasterKeyInfo, data_key: bytes, encrypted_data_key: bytes
    ) -> None: ...

class EncryptedDataKey:
    key_provider: MasterKeyInfo
    encrypted_data_key: bytes
    def __init__(self, key_provider: MasterKeyInfo, encrypted_data_key: bytes) -> None: ...

class MessageHeader:
    version: SerializationVersion
    algorithm: Algorithm
    message_id: bytes
    encryption_context: Dict[str, str]
    encrypted_data_keys: Set[EncryptedDataKey]
    content_type: ContentType
    frame_length: int
    type: Optional[ObjectType]
    content_aad_length: Optional[int]
    header_iv_length: Optional[int]
    commitment_key: Optional[bytes]
    def __init__(
        self,
        version: SerializationVersion,
        algorithm: Algorithm,
        message_id: bytes,
        encryption_context: Dict[str, str],
        encrypted_data_keys: Set[EncryptedDataKey],
        content_type: ContentType,
        frame_length: int,
        type: Optional[ObjectType] = ...,
        content_aad_length: Optional[int] = ...,
        header_iv_length: Optional[int] = ...,
        commitment_key: Optional[bytes] = ...,
    ) -> None: ...
