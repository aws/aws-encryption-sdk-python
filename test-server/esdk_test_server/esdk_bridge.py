# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Delegation to the real AWS Encryption SDK for Python.

Translates the modeled ``ESDKClientConfig`` (a tagged-union-via-optional-members
CBOR map, mirroring the single Smithy model at the lowest faithful API layer) into
a real ESDK client backed by a Material Providers Library keyring / cryptographic
materials manager, and drives the one-shot and streaming encrypt/decrypt APIs.

The MPL model shapes and enums mirror the Java server's ``EsdkClientFactory``
one-for-one, so the two languages build equivalent clients from the same config.
"""

import os

import boto3
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.identifiers import Algorithm

from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl import models as mpl
from aws_cryptographic_material_providers.keystore import KeyStore
from aws_cryptographic_material_providers.keystore.config import KeyStoreConfig
from aws_cryptographic_material_providers.keystore.models import KMSConfigurationKmsKeyArn


class ClientError(Exception):
    """A failure originating in the ESDK itself: forwarded as ESDKClientError."""


class ServerError(Exception):
    """A framework/config failure: forwarded as GenericServerError."""


_MATERIAL_PROVIDERS = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())


def _region():
    """Resolve the AWS region for KMS clients (mirrors the Java server default)."""
    return (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or os.environ.get("ESDK_TESTSERVER_KMS_REGION")
        or "us-west-2"
    )


def _kms_client():
    return boto3.client("kms", region_name=_region())


def _kms_client_for_key(kms_key_id):
    """A KMS client in the key's own region.

    KMS rejects an ARN whose region differs from the client's region ("Invalid
    arn <region>"), so a us-east-1 key needs a us-east-1 client even when the
    default region is us-west-2. Falls back to the default region for a bare key
    id or alias that carries no region.
    """
    region = _region()
    if isinstance(kms_key_id, str) and kms_key_id.startswith("arn:"):
        parts = kms_key_id.split(":")
        if len(parts) > 3 and parts[3]:
            region = parts[3]
    return boto3.client("kms", region_name=region)


def to_algorithm(model_suite_id):
    """Map a modeled ``ESDKAlgorithmSuiteId`` to a Python ``Algorithm`` member.

    The model ids are the Python names prefixed with ``ALG_``; the non-KDF suites
    additionally carry a ``_NO_KDF`` suffix the Python enum omits.
    """
    name = model_suite_id
    if name.startswith("ALG_"):
        name = name[len("ALG_"):]
    if name.endswith("_NO_KDF"):
        name = name[: -len("_NO_KDF")]
    try:
        return getattr(Algorithm, name)
    except AttributeError as exc:
        raise ServerError(f"unknown algorithm suite id: {model_suite_id}") from exc


# Modeled ESDKAlgorithmSuiteId names, used to invert to_algorithm() so decrypt can
# report the suite it determined from the message header.
_MODEL_SUITE_IDS = (
    "ALG_AES_128_GCM_IV12_TAG16_NO_KDF",
    "ALG_AES_192_GCM_IV12_TAG16_NO_KDF",
    "ALG_AES_256_GCM_IV12_TAG16_NO_KDF",
    "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256",
    "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256",
    "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256",
    "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256",
    "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
    "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
    "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY",
    "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
)


def from_algorithm(algorithm):
    """Inverse of to_algorithm: a Python ``Algorithm`` -> modeled ESDKAlgorithmSuiteId name."""
    for model_suite_id in _MODEL_SUITE_IDS:
        if to_algorithm(model_suite_id) == algorithm:
            return model_suite_id
    return None


def _commitment_policy(value):
    try:
        return getattr(CommitmentPolicy, value)
    except AttributeError as exc:
        raise ServerError(f"unknown commitment policy: {value}") from exc


def _one_variant(tagged, what):
    """Return the single (name, value) set on a tagged-union map, else reject.

    Enforces the "exactly one optional variant member set" invariant at runtime
    (Requirements 2.3, 2.4).
    """
    present = [(k, v) for k, v in tagged.items() if v is not None]
    if len(present) != 1:
        raise ClientError(
            f"exactly one {what} variant must be set, found {len(present)}: "
            f"{sorted(k for k, _ in present)}"
        )
    return present[0]


# ---------------------------------------------------------------------------
# Keyring construction (tagged union via optional members; recursive for Multi).
# ---------------------------------------------------------------------------
def _build_keyring(keyring):
    name, cfg = _one_variant(keyring, "keyring")
    if name == "RawAes":
        return _MATERIAL_PROVIDERS.create_raw_aes_keyring(
            input=mpl.CreateRawAesKeyringInput(
                key_namespace=cfg["keyNamespace"],
                key_name=cfg["keyName"],
                wrapping_key=cfg["wrappingKey"],
                wrapping_alg=getattr(mpl.AesWrappingAlg, cfg["wrappingAlg"]),
            )
        )
    if name == "RawRsa":
        return _MATERIAL_PROVIDERS.create_raw_rsa_keyring(
            input=mpl.CreateRawRsaKeyringInput(
                key_namespace=cfg["keyNamespace"],
                key_name=cfg["keyName"],
                padding_scheme=getattr(mpl.PaddingScheme, cfg["paddingScheme"]),
                public_key=cfg.get("publicKey"),
                private_key=cfg.get("privateKey"),
            )
        )
    if name == "AwsKms":
        return _MATERIAL_PROVIDERS.create_aws_kms_keyring(
            input=mpl.CreateAwsKmsKeyringInput(
                kms_key_id=cfg["kmsKeyId"],
                kms_client=_kms_client_for_key(cfg["kmsKeyId"]),
                grant_tokens=cfg.get("grantTokens"),
            )
        )
    if name == "AwsKmsMrk":
        return _MATERIAL_PROVIDERS.create_aws_kms_mrk_keyring(
            input=mpl.CreateAwsKmsMrkKeyringInput(
                kms_key_id=cfg["kmsKeyId"],
                kms_client=_kms_client_for_key(cfg["kmsKeyId"]),
                grant_tokens=cfg.get("grantTokens"),
            )
        )
    if name == "AwsKmsMultiKeyring":
        return _MATERIAL_PROVIDERS.create_aws_kms_multi_keyring(
            input=mpl.CreateAwsKmsMultiKeyringInput(
                generator=cfg.get("generator"),
                kms_key_ids=cfg.get("kmsKeyIds"),
            )
        )
    if name == "AwsKmsMrkMultiKeyring":
        # MRK-aware multi-keyring: an optional MRK generator + child MRK key ids.
        # Mirrors AwsKmsMultiKeyring (the MPL builds its own default KMS client
        # supplier); the MRK-aware form matches multi-region keys on decrypt.
        return _MATERIAL_PROVIDERS.create_aws_kms_mrk_multi_keyring(
            input=mpl.CreateAwsKmsMrkMultiKeyringInput(
                generator=cfg.get("generator"),
                kms_key_ids=cfg.get("kmsKeyIds"),
            )
        )
    if name == "AwsKmsDiscovery":
        return _MATERIAL_PROVIDERS.create_aws_kms_discovery_keyring(
            input=mpl.CreateAwsKmsDiscoveryKeyringInput(
                kms_client=_kms_client(),
                discovery_filter=_discovery_filter(cfg.get("discoveryFilter")),
                grant_tokens=cfg.get("grantTokens"),
            )
        )
    if name == "AwsKmsMrkDiscovery":
        return _MATERIAL_PROVIDERS.create_aws_kms_mrk_discovery_keyring(
            input=mpl.CreateAwsKmsMrkDiscoveryKeyringInput(
                kms_client=boto3.client("kms", region_name=cfg["region"]),
                region=cfg["region"],
                discovery_filter=_discovery_filter(cfg.get("discoveryFilter")),
                grant_tokens=cfg.get("grantTokens"),
            )
        )
    if name == "AwsKmsRsa":
        kms_client = _kms_client_for_key(cfg["kmsKeyId"])
        public_key = cfg.get("publicKey")
        if public_key is None:
            # Fetch the RSA public key from KMS (as the Java server does) so the
            # keyring can OnEncrypt. KMS GetPublicKey returns DER (X.509
            # SubjectPublicKeyInfo); CreateAwsKmsRsaKeyring expects PEM.
            der = kms_client.get_public_key(KeyId=cfg["kmsKeyId"])["PublicKey"]
            public_key = _der_to_public_key_pem(der)
        return _MATERIAL_PROVIDERS.create_aws_kms_rsa_keyring(
            input=mpl.CreateAwsKmsRsaKeyringInput(
                kms_key_id=cfg["kmsKeyId"],
                encryption_algorithm=cfg.get("encryptionAlgorithm"),
                public_key=public_key,
                kms_client=kms_client,
                grant_tokens=cfg.get("grantTokens"),
            )
        )
    if name == "Multi":
        children = [_build_keyring(k) for k in cfg["childKeyrings"]]
        generator = _build_keyring(cfg["generator"]) if cfg.get("generator") else None
        return _MATERIAL_PROVIDERS.create_multi_keyring(
            input=mpl.CreateMultiKeyringInput(child_keyrings=children, generator=generator)
        )
    if name == "AwsKmsHierarchical":
        key_store = KeyStore(
            config=KeyStoreConfig(
                ddb_client=boto3.client("dynamodb", region_name=_region()),
                ddb_table_name=cfg["keyStoreTableName"],
                logical_key_store_name=cfg["logicalKeyStoreName"],
                kms_client=_kms_client(),
                kms_configuration=KMSConfigurationKmsKeyArn(value=cfg["kmsKeyArn"]),
            )
        )
        return _MATERIAL_PROVIDERS.create_aws_kms_hierarchical_keyring(
            input=mpl.CreateAwsKmsHierarchicalKeyringInput(
                key_store=key_store,
                branch_key_id=cfg["branchKeyId"],
                ttl_seconds=cfg["ttlSeconds"],
                cache=mpl.CacheTypeDefault(value=mpl.DefaultCache(entry_capacity=100)),
            )
        )
    raise ClientError(f"unsupported keyring variant: {name}")


def _discovery_filter(filt):
    if not filt:
        return None
    return mpl.DiscoveryFilter(partition=filt["partition"], account_ids=filt["accountIds"])


def _der_to_public_key_pem(der_bytes):
    """Wrap DER (X.509 SubjectPublicKeyInfo) bytes as a PEM ``PUBLIC KEY`` block.

    Pass through unchanged if the bytes already look like PEM.
    """
    if der_bytes[:11] == b"-----BEGIN ":
        return der_bytes
    import base64

    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
    return pem.encode("ascii")


# ---------------------------------------------------------------------------
# CMM construction (tagged union; recursive for RequiredEncryptionContext).
# ---------------------------------------------------------------------------
def _build_cmm(cmm):
    name, cfg = _one_variant(cmm, "cmm")
    if name == "Default":
        return _MATERIAL_PROVIDERS.create_default_cryptographic_materials_manager(
            input=mpl.CreateDefaultCryptographicMaterialsManagerInput(
                keyring=_build_keyring(cfg["keyring"])
            )
        )
    if name == "RequiredEncryptionContext":
        return _MATERIAL_PROVIDERS.create_required_encryption_context_cmm(
            input=mpl.CreateRequiredEncryptionContextCMMInput(
                underlying_cmm=_build_cmm(cfg["underlyingCMM"]),
                required_encryption_context_keys=cfg["requiredEncryptionContextKeys"],
            )
        )
    if name == "Caching":
        raise ClientError(
            "Caching CMM is not exercised by the round-trip Tests and is not supported here"
        )
    raise ClientError(f"unsupported cmm variant: {name}")


class EsdkClientBundle:
    """A configured ESDK client plus its materials manager and commitment policy."""

    def __init__(self, client, materials_manager):
        self._client = client
        self._cmm = materials_manager

    def _common_kwargs(self, encryption_context, algorithm_suite_id, frame_length):
        kwargs = {"materials_manager": self._cmm}
        if encryption_context:
            kwargs["encryption_context"] = encryption_context
        if algorithm_suite_id:
            kwargs["algorithm"] = to_algorithm(algorithm_suite_id)
        if frame_length is not None:
            kwargs["frame_length"] = frame_length
        return kwargs

    def encrypt(self, plaintext, encryption_context, algorithm_suite_id, frame_length):
        kwargs = self._common_kwargs(encryption_context, algorithm_suite_id, frame_length)
        ciphertext, _ = self._client.encrypt(source=plaintext, **kwargs)
        return ciphertext

    def decrypt(self, ciphertext, encryption_context):
        kwargs = {"materials_manager": self._cmm}
        if encryption_context:
            kwargs["encryption_context"] = encryption_context
        plaintext, header = self._client.decrypt(source=ciphertext, **kwargs)
        return plaintext, dict(header.encryption_context or {}), from_algorithm(header.algorithm)

    def encrypt_stream(self, plaintext, encryption_context, algorithm_suite_id, frame_length,
                       plaintext_length_bound=None):
        kwargs = self._common_kwargs(encryption_context, algorithm_suite_id, frame_length)
        if plaintext_length_bound is not None:
            # The Python ESDK enforces the plaintext length bound via source_length:
            # the total plaintext encrypted is not allowed to exceed it.
            kwargs["source_length"] = plaintext_length_bound
        with self._client.stream(mode="e", source=plaintext, **kwargs) as encryptor:
            return encryptor.read()

    def decrypt_stream(self, ciphertext, encryption_context):
        kwargs = {"materials_manager": self._cmm}
        if encryption_context:
            kwargs["encryption_context"] = encryption_context
        with self._client.stream(mode="d", source=ciphertext, **kwargs) as decryptor:
            plaintext = decryptor.read()
            header = decryptor.header
        return plaintext, dict(header.encryption_context or {}), from_algorithm(header.algorithm)


def build_client(config):
    """Build an :class:`EsdkClientBundle` from a modeled ``ESDKClientConfig`` map.

    A construction failure surfaces as a ServerError (GenericServerError,
    Requirement 3.6), except an exactly-one-variant violation which is a
    ClientError (ESDKClientError, Requirements 2.3, 2.4).
    """
    commitment = _commitment_policy(config["commitmentPolicy"])
    cmm = _build_cmm(config["cmm"])
    client_kwargs = {"commitment_policy": commitment}
    max_edks = config.get("maxEncryptedDataKeys")
    if max_edks is not None:
        client_kwargs["max_encrypted_data_keys"] = max_edks
    client = aws_encryption_sdk.EncryptionSDKClient(**client_kwargs)
    return EsdkClientBundle(client, cmm)
