# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import sys
from typing import Any, BinaryIO, Dict, IO, Optional, Tuple, Union, overload

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.caches.null import NullCryptoMaterialsCache
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy, __version__
from aws_encryption_sdk.internal.utils.signature import SignaturePolicy
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryAwsKmsMasterKeyProvider,
    KMSMasterKeyProviderConfig,
    StrictAwsKmsMasterKeyProvider,
)
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager
from aws_encryption_sdk.streaming_client import (
    DecryptorConfig,
    EncryptorConfig,
    StreamDecryptor,
    StreamEncryptor,
)
from aws_encryption_sdk.structures import MessageHeader

__all__ = [
    "LocalCryptoMaterialsCache",
    "NullCryptoMaterialsCache",
    "AWSEncryptionSDKClientError",
    "Algorithm",
    "CommitmentPolicy",
    "SignaturePolicy",
    "DiscoveryAwsKmsMasterKeyProvider",
    "KMSMasterKeyProviderConfig",
    "StrictAwsKmsMasterKeyProvider",
    "CachingCryptoMaterialsManager",
    "DefaultCryptoMaterialsManager",
    "DecryptorConfig",
    "EncryptorConfig",
    "StreamDecryptor",
    "StreamEncryptor",
    "MessageHeader",
    "EncryptionSDKClientConfig",
    "EncryptionSDKClient",
    "__version__",
]

class EncryptionSDKClientConfig:
    commitment_policy: CommitmentPolicy
    max_encrypted_data_keys: Optional[int]
    def __init__(
        self,
        commitment_policy: CommitmentPolicy = ...,
        max_encrypted_data_keys: Optional[int] = ...,
    ) -> None: ...

class EncryptionSDKClient:
    config: EncryptionSDKClientConfig
    def __init__(
        self,
        config: Optional[EncryptionSDKClientConfig] = ...,
        commitment_policy: Optional[CommitmentPolicy] = ...,
        max_encrypted_data_keys: Optional[int] = ...,
        **kwargs: Any,
    ) -> None: ...
    def encrypt(
        self,
        source: Union[str, bytes, IO[bytes], BinaryIO],
        materials_manager: Optional[CryptoMaterialsManager] = ...,
        key_provider: Optional[Any] = ...,
        keyring: Optional[Any] = ...,
        source_length: Optional[int] = ...,
        encryption_context: Optional[Dict[str, str]] = ...,
        algorithm: Optional[Algorithm] = ...,
        frame_length: Optional[int] = ...,
        config: Optional[EncryptorConfig] = ...,
        **kwargs: Any,
    ) -> Tuple[bytes, MessageHeader]: ...
    def decrypt(
        self,
        source: Union[str, bytes, IO[bytes], BinaryIO],
        materials_manager: Optional[CryptoMaterialsManager] = ...,
        key_provider: Optional[Any] = ...,
        keyring: Optional[Any] = ...,
        source_length: Optional[int] = ...,
        encryption_context: Optional[Dict[str, str]] = ...,
        max_body_length: Optional[int] = ...,
        config: Optional[DecryptorConfig] = ...,
        **kwargs: Any,
    ) -> Tuple[bytes, MessageHeader]: ...
    @overload
    def stream(
        self,
        mode: Literal["e", "encrypt"],
        source: Optional[Union[str, bytes, IO[bytes], BinaryIO]] = ...,
        materials_manager: Optional[CryptoMaterialsManager] = ...,
        key_provider: Optional[Any] = ...,
        keyring: Optional[Any] = ...,
        source_length: Optional[int] = ...,
        encryption_context: Optional[Dict[str, str]] = ...,
        algorithm: Optional[Algorithm] = ...,
        frame_length: Optional[int] = ...,
        config: Optional[EncryptorConfig] = ...,
        **kwargs: Any,
    ) -> StreamEncryptor: ...
    @overload
    def stream(
        self,
        mode: Literal["d", "decrypt", "decrypt-unsigned"],
        source: Optional[Union[str, bytes, IO[bytes], BinaryIO]] = ...,
        materials_manager: Optional[CryptoMaterialsManager] = ...,
        key_provider: Optional[Any] = ...,
        keyring: Optional[Any] = ...,
        source_length: Optional[int] = ...,
        encryption_context: Optional[Dict[str, str]] = ...,
        max_body_length: Optional[int] = ...,
        config: Optional[DecryptorConfig] = ...,
        **kwargs: Any,
    ) -> StreamDecryptor: ...
    @overload
    def stream(
        self,
        mode: str,
        source: Optional[Union[str, bytes, IO[bytes], BinaryIO]] = ...,
        **kwargs: Any,
    ) -> Union[StreamEncryptor, StreamDecryptor]: ...
