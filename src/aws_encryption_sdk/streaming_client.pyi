# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import types
from typing import Any, BinaryIO, Dict, IO, Iterator, Optional, Type, Union
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.structures import MessageHeader

class _ClientConfig:
    materials_manager: CryptoMaterialsManager
    source: Any
    source_length: Optional[int]
    def __init__(
        self,
        materials_manager: Optional[CryptoMaterialsManager] = ...,
        source: Optional[Union[str, bytes, IO[bytes], BinaryIO]] = ...,
        source_length: Optional[int] = ...,
        key_provider: Optional[Any] = ...,
        keyring: Optional[Any] = ...,
        **kwargs: Any,
    ) -> None: ...

class EncryptorConfig(_ClientConfig):
    encryption_context: Dict[str, str]
    algorithm: Algorithm
    frame_length: int
    commitment_policy: CommitmentPolicy
    max_encrypted_data_keys: Optional[int]
    def __init__(
        self,
        encryption_context: Optional[Dict[str, str]] = ...,
        algorithm: Optional[Algorithm] = ...,
        frame_length: Optional[int] = ...,
        commitment_policy: Optional[CommitmentPolicy] = ...,
        max_encrypted_data_keys: Optional[int] = ...,
        **kwargs: Any,
    ) -> None: ...

class DecryptorConfig(_ClientConfig):
    max_body_length: Optional[int]
    commitment_policy: CommitmentPolicy
    max_encrypted_data_keys: Optional[int]
    encryption_context: Optional[Dict[str, str]]
    def __init__(
        self,
        max_body_length: Optional[int] = ...,
        commitment_policy: Optional[CommitmentPolicy] = ...,
        max_encrypted_data_keys: Optional[int] = ...,
        encryption_context: Optional[Dict[str, str]] = ...,
        **kwargs: Any,
    ) -> None: ...

class _EncryptionStream:
    header: MessageHeader
    config: _ClientConfig
    def __init__(self, **kwargs: Any) -> None: ...
    def read(self, size: Optional[int] = ...) -> bytes: ...
    def close(self) -> None: ...
    def closed(self) -> bool: ...
    def __enter__(self) -> _EncryptionStream: ...
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[types.TracebackType],
    ) -> None: ...
    def __iter__(self) -> Iterator[bytes]: ...
    def __next__(self) -> bytes: ...

class StreamEncryptor(_EncryptionStream):
    config: EncryptorConfig
    def __enter__(self) -> StreamEncryptor: ...

class StreamDecryptor(_EncryptionStream):
    config: DecryptorConfig
    def __enter__(self) -> StreamDecryptor: ...
