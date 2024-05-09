# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""High level AWS Encryption SDK client functions."""
# Below are imported for ease of use by implementors
import warnings

import attr

from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache  # noqa
from aws_encryption_sdk.caches.null import NullCryptoMaterialsCache  # noqa
from aws_encryption_sdk.compatability import _warn_deprecated_python
from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError  # noqa
from aws_encryption_sdk.identifiers import Algorithm, CommitmentPolicy, __version__  # noqa
from aws_encryption_sdk.internal.utils.signature import SignaturePolicy  # noqa
from aws_encryption_sdk.key_providers.kms import (  # noqa
    DiscoveryAwsKmsMasterKeyProvider,
    KMSMasterKeyProviderConfig,
    StrictAwsKmsMasterKeyProvider,
)
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager  # noqa
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager  # noqa
from aws_encryption_sdk.streaming_client import (  # noqa
    DecryptorConfig,
    EncryptorConfig,
    StreamDecryptor,
    StreamEncryptor,
)

_warn_deprecated_python()


@attr.s(hash=True)
class EncryptionSDKClientConfig(object):
    """Configuration object for EncryptionSDKClients

    :param commitment_policy: The commitment policy to apply to encryption and decryption requests
    :type commitment_policy: aws_encryption_sdk.materials_manager.identifiers.CommitmentPolicy
    :param max_encrypted_data_keys: The maximum number of encrypted data keys to allow during
    encryption and decryption
    :type max_encrypted_data_keys: None or positive int
    """

    commitment_policy = attr.ib(
        hash=True,
        default=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        validator=attr.validators.instance_of(CommitmentPolicy),
    )
    max_encrypted_data_keys = attr.ib(
        hash=True, validator=attr.validators.optional(attr.validators.instance_of(int)), default=None
    )

    def __attrs_post_init__(self):
        """Applies post-processing which cannot be handled by attrs."""
        if self.max_encrypted_data_keys is not None and self.max_encrypted_data_keys < 1:
            raise ValueError("max_encrypted_data_keys cannot be less than 1")


class EncryptionSDKClient(object):
    """A client providing high level AWS Encryption SDK client methods."""

    _config_class = EncryptionSDKClientConfig

    def __new__(cls, **kwargs):
        """Constructs a new EncryptionSDKClient instance."""
        instance = super(EncryptionSDKClient, cls).__new__(cls)

        config = kwargs.pop("config", None)
        if not isinstance(config, instance._config_class):  # pylint: disable=protected-access
            config = instance._config_class(**kwargs)  # pylint: disable=protected-access
        instance.config = config
        return instance

    def _set_config_kwargs(self, callee_name, kwargs_dict):
        """
        Copy relevant StreamEncryptor/StreamDecryptor configuration from `self.config` into `kwargs`,
        raising and exception if the keys already exist in `kwargs`.
        """
        for key in ("commitment_policy", "max_encrypted_data_keys"):
            if key in kwargs_dict:
                warnings.warn(
                    "Invalid keyword argument '{key}' passed to {callee}. "
                    "Set this value by passing a 'config' to the EncryptionSDKClient constructor instead.".format(
                        key=key, callee=callee_name
                    )
                )
        kwargs_dict["commitment_policy"] = self.config.commitment_policy
        kwargs_dict["max_encrypted_data_keys"] = self.config.max_encrypted_data_keys

    def encrypt(self, **kwargs):
        """Encrypts and serializes provided plaintext.

        .. note::
            When using this function, the entire ciphertext message is encrypted into memory before returning
            any data.  If streaming is desired, see :class:`aws_encryption_sdk.stream`.

        .. code:: python

            >>> import boto3
            >>> from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
            >>> from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
            >>> from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
            >>> from aws_cryptographic_materialproviders.mpl.references import IKeyring
            >>> import aws_encryption_sdk
            >>> client = aws_encryption_sdk.EncryptionSDKClient()
            >>> mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
            ...     config=MaterialProvidersConfig()
            ... )
            >>> keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
            ...     kms_key_id='arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
            ...     kms_client=boto3.client('kms', region_name="us-west-2")
            ... )
            >>> kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
            ...     input=keyring_input
            ... )
            >>> my_ciphertext, encryptor_header = client.encrypt(
            ...     source=my_plaintext,
            ...     keyring=kms_keyring
            ... )

        :param config: Client configuration object (config or individual parameters required)
        :type config: aws_encryption_sdk.streaming_client.EncryptorConfig
        :param source: Source data to encrypt or decrypt
        :type source: str, bytes, io.IOBase, or file
        :param materials_manager: `CryptoMaterialsManager` that returns cryptographic materials
            (requires either `materials_manager` or `keyring`)
        :type materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
        :param key_provider: `MasterKeyProvider` that returns data keys for encryption
            (requires either `materials_manager` or `key_provider`)
        :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
        :param keyring: `IKeyring` that returns keyring for encryption
            (requires either `materials_manager` or `keyring`)
        :type keyring: aws_cryptographic_materialproviders.mpl.references.IKeyring
        :param int source_length: Length of source data (optional)

            .. note::
                If source_length is not provided and unframed message is being written or read() is called,
                will attempt to seek() to the end of the stream and tell() to find the length of source data.

            .. note::
                If `source_length` and `materials_manager` are both provided, the total plaintext bytes
                encrypted will not be allowed to exceed `source_length`. To maintain backwards compatibility,
                this is not enforced if a `keyring` is provided.

        :param dict encryption_context: Dictionary defining encryption context
        :param algorithm: Algorithm to use for encryption
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param int frame_length: Frame length in bytes
        :returns: Tuple containing the encrypted ciphertext and the message header object
        :rtype: tuple of bytes and :class:`aws_encryption_sdk.structures.MessageHeader`
        """
        self._set_config_kwargs("encrypt", kwargs)
        kwargs["signature_policy"] = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT
        with StreamEncryptor(**kwargs) as encryptor:
            ciphertext = encryptor.read()
        return ciphertext, encryptor.header

    def decrypt(self, **kwargs):
        """Deserializes and decrypts provided ciphertext.

        .. note::
            When using this function, the entire ciphertext message is decrypted into memory before returning
            any data.  If streaming is desired, see :class:`aws_encryption_sdk.stream`.

        .. code:: python

            >>> import boto3
            >>> from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
            >>> from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
            >>> from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
            >>> from aws_cryptographic_materialproviders.mpl.references import IKeyring
            >>> import aws_encryption_sdk
            >>> client = aws_encryption_sdk.EncryptionSDKClient()
            >>> mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
            ...     config=MaterialProvidersConfig()
            ... )
            >>> keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
            ...     kms_key_id='arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
            ...     kms_client=boto3.client('kms', region_name="us-west-2")
            ... )
            >>> kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
            ...     input=keyring_input
            ... )
            >>> my_plaintext, decryptor_header = client.decrypt(
            ...     source=my_ciphertext,
            ...     keyring=kms_keyring
            ... )

        :param config: Client configuration object (config or individual parameters required)
        :type config: aws_encryption_sdk.streaming_client.DecryptorConfig
        :param source: Source data to encrypt or decrypt
        :type source: str, bytes, io.IOBase, or file
        :param materials_manager: `CryptoMaterialsManager` that returns cryptographic materials
            (requires either `materials_manager` or `keyring`)
        :type materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
        :param key_provider: `MasterKeyProvider` that returns data keys for decryption
            (requires either `materials_manager` or `key_provider`)
        :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
        :param keyring: `IKeyring` that returns keyring for encryption
            (requires either `materials_manager` or `keyring`)
        :type keyring: aws_cryptographic_materialproviders.mpl.references.IKeyring
        :param int source_length: Length of source data (optional)

            .. note::
                If source_length is not provided and read() is called, will attempt to seek()
                to the end of the stream and tell() to find the length of source data.

        :param dict encryption_context: Dictionary defining encryption context to validate
            on decrypt. This is ONLY validated on decrypt if using the required encryption
            context CMM from the aws-cryptographic-materialproviders library.
        :param int max_body_length: Maximum frame size (or content length for non-framed messages)
            in bytes to read from ciphertext message.
        :returns: Tuple containing the decrypted plaintext and the message header object
        :rtype: tuple of bytes and :class:`aws_encryption_sdk.structures.MessageHeader`
        """
        self._set_config_kwargs("decrypt", kwargs)
        kwargs["signature_policy"] = SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT
        with StreamDecryptor(**kwargs) as decryptor:
            plaintext = decryptor.read()
        return plaintext, decryptor.header

    def stream(self, **kwargs):
        """Provides an :py:func:`open`-like interface to the streaming encryptor/decryptor classes.

        .. warning::
            Take care when decrypting framed messages with large frame length and large non-framed
            messages. In order to protect the authenticity of the encrypted data, no plaintext
            is returned until it has been authenticated. Because of this, potentially large amounts
            of data may be read into memory.  In the case of framed messages, the entire contents
            of each frame are read into memory and authenticated before returning any plaintext.
            In the case of non-framed messages, the entire message is read into memory and
            authenticated before returning any plaintext.  The authenticated plaintext is held in
            memory until it is requested.

        .. note::
            Consequently, keep the above decrypting consideration in mind when encrypting messages
            to ensure that issues are not encountered when decrypting those messages.

        .. code:: python

            >>> import boto3
            >>> from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
            >>> from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
            >>> from aws_cryptographic_materialproviders.mpl.models import CreateAwsKmsKeyringInput
            >>> from aws_cryptographic_materialproviders.mpl.references import IKeyring
            >>> import aws_encryption_sdk
            >>> client = aws_encryption_sdk.EncryptionSDKClient()
            >>> mat_prov: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
            ...     config=MaterialProvidersConfig()
            ... )
            >>> keyring_input: CreateAwsKmsKeyringInput = CreateAwsKmsKeyringInput(
            ...     kms_key_id='arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
            ...     kms_client=boto3.client('kms', region_name="us-west-2")
            ... )
            >>> kms_keyring: IKeyring = mat_prov.create_aws_kms_keyring(
            ...     input=keyring_input
            ... )
            >>> plaintext_filename = 'my-secret-data.dat'
            >>> ciphertext_filename = 'my-encrypted-data.ct'
            >>> with open(plaintext_filename, 'rb') as pt_file, open(ciphertext_filename, 'wb') as ct_file:
            ...     with client.stream(
            ...         mode='e',
            ...         source=pt_file,
            ...         keyring=kms_keyring
            ...     ) as encryptor:
            ...         for chunk in encryptor:
            ...             ct_file.write(chunk)
            >>> decrypted_filename = 'my-decrypted-data.dat'
            >>> with open(ciphertext_filename, 'rb') as ct_file, open(decrypted_filename, 'wb') as pt_file:
            ...     with client.stream(
            ...         mode='d',
            ...         source=ct_file,
            ...         keyring=kms_keyring
            ...     ) as decryptor:
            ...         for chunk in decryptor:
            ...             pt_file.write(chunk)

        :param str mode: Type of streaming client to return (e/encrypt: encryptor, d/decrypt: decryptor)
        :param **kwargs: All other parameters provided are passed to the appropriate Streaming client
        :returns: Streaming Encryptor or Decryptor, as requested
        :rtype: :class:`aws_encryption_sdk.streaming_client.StreamEncryptor`
            or :class:`aws_encryption_sdk.streaming_client.StreamDecryptor`
        :raises ValueError: if supplied with an unsupported mode value
        """
        self._set_config_kwargs("stream", kwargs)
        mode = kwargs.pop("mode")

        _signature_policy_map = {
            "e": SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
            "encrypt": SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
            "d": SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
            "decrypt": SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
            "decrypt-unsigned": SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT,
        }
        kwargs["signature_policy"] = _signature_policy_map[mode.lower()]

        _stream_map = {
            "e": StreamEncryptor,
            "encrypt": StreamEncryptor,
            "d": StreamDecryptor,
            "decrypt": StreamDecryptor,
            "decrypt-unsigned": StreamDecryptor,
        }
        try:
            return _stream_map[mode.lower()](**kwargs)
        except KeyError:
            raise ValueError("Unsupported mode: {}".format(mode))
