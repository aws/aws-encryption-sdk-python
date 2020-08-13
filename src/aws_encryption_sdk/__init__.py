# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""High level AWS Encryption SDK client functions."""
import copy

# Below are imported for ease of use by implementors
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache  # noqa
from aws_encryption_sdk.caches.null import NullCryptoMaterialsCache  # noqa
from aws_encryption_sdk.identifiers import Algorithm, __version__  # noqa
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider, KMSMasterKeyProviderConfig  # noqa
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager  # noqa
from aws_encryption_sdk.materials_managers.default import DefaultCryptoMaterialsManager  # noqa
from aws_encryption_sdk.streaming_client import (  # noqa
    DecryptorConfig,
    EncryptorConfig,
    StreamDecryptor,
    StreamEncryptor,
)
from aws_encryption_sdk.structures import CryptoResult

__all__ = ("encrypt", "decrypt", "stream")


def encrypt(**kwargs):
    """Encrypts and serializes provided plaintext.

    .. note::
        When using this function, the entire ciphertext message is encrypted into memory before returning
        any data.  If streaming is desired, see :class:`aws_encryption_sdk.stream`.

    .. versionadded:: 2.0.0
       The *keyring* parameter.

    .. versionadded:: 2.0.0

        For backwards compatibility,
        the new :class:`CryptoResult` return value also unpacks like a 2-member tuple.
        This allows for backwards compatibility with the previous outputs
        so this change should not break any existing consumers.

    .. code:: python

        >>> import aws_encryption_sdk
        >>> from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
        >>> keyring = AwsKmsKeyring(
        ...     generator_key_id="arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222",
        ...     key_ids=["arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333"],
        ... )
        >>> my_ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
        ...     source=my_plaintext,
        ...     keyring=keyring,
        >>> )

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.EncryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param CryptoMaterialsManager materials_manager:
        Cryptographic materials manager to use for encryption
        (either ``materials_manager``, ``keyring``, ``key_provider`` required)
    :param Keyring keyring: Keyring to use for encryption
        (either ``materials_manager``, ``keyring``, ``key_provider`` required)
    :param MasterKeyProvider key_provider:
        Master key provider to use for encryption
        (either ``materials_manager``, ``keyring``, ``key_provider`` required)
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.

        .. note::
            .. versionadded:: 1.3.0

            If `source_length` and `materials_manager` are both provided, the total plaintext bytes
            encrypted will not be allowed to exceed `source_length`. To maintain backwards compatibility,
            this is not enforced if a `key_provider` is provided.

    :param dict encryption_context: Dictionary defining encryption context
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int frame_length: Frame length in bytes
    :returns: Encrypted message and message metadata (header)
    :rtype: CryptoResult
    """
    with StreamEncryptor(**kwargs) as encryptor:
        ciphertext = encryptor.read()

    header_copy = copy.deepcopy(encryptor.header)

    return CryptoResult(result=ciphertext, header=header_copy)


def decrypt(**kwargs):
    """Deserializes and decrypts provided ciphertext.

    .. note::
        When using this function, the entire ciphertext message is decrypted into memory before returning
        any data.  If streaming is desired, see :class:`aws_encryption_sdk.stream`.

    .. versionadded:: 2.0.0
       The *keyring* parameter.

    .. versionadded:: 2.0.0

        For backwards compatibility,
        the new :class:`CryptoResult` return value also unpacks like a 2-member tuple.
        This allows for backwards compatibility with the previous outputs
        so this change should not break any existing consumers.

    .. code:: python

        >>> import aws_encryption_sdk
        >>> from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
        >>> keyring = AwsKmsKeyring(
        ...     generator_key_id="arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222",
        ...     key_ids=["arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333"],
        ... )
        >>> my_ciphertext, decryptor_header = aws_encryption_sdk.decrypt(
        ...     source=my_ciphertext,
        ...     keyring=keyring,
        ... )

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.DecryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param CryptoMaterialsManager materials_manager:
        Cryptographic materials manager to use for encryption
        (either ``materials_manager``, ``keyring``, ``key_provider`` required)
    :param Keyring keyring: Keyring to use for encryption
        (either ``materials_manager``, ``keyring``, ``key_provider`` required)
    :param MasterKeyProvider key_provider:
        Master key provider to use for encryption
        (either ``materials_manager``, ``keyring``, ``key_provider`` required)
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and read() is called, will attempt to seek()
            to the end of the stream and tell() to find the length of source data.

    :param int max_body_length: Maximum frame size (or content length for non-framed messages)
        in bytes to read from ciphertext message.
    :returns: Decrypted plaintext and message metadata (header)
    :rtype: CryptoResult
    """
    with StreamDecryptor(**kwargs) as decryptor:
        plaintext = decryptor.read()

    header_copy = copy.deepcopy(decryptor.header)

    return CryptoResult(result=plaintext, header=header_copy)


def stream(**kwargs):
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

        >>> import aws_encryption_sdk
        >>> from aws_encryption_sdk.keyrings.aws_kms import AwsKmsKeyring
        >>> keyring = AwsKmsKeyring(
        ...     generator_key_id="arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222",
        ...     key_ids=["arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333"],
        ... )
        >>> plaintext_filename = 'my-secret-data.dat'
        >>> ciphertext_filename = 'my-encrypted-data.ct'
        >>> with open(plaintext_filename, 'rb') as pt_file, open(ciphertext_filename, 'wb') as ct_file:
        ...      with aws_encryption_sdk.stream(
        ...         mode='e',
        ...         source=pt_file,
        ...         keyring=keyring,
        ...     ) as encryptor:
        ...         for chunk in encryptor:
        ...              ct_file.write(chunk)
        >>> new_plaintext_filename = 'my-decrypted-data.dat'
        >>> with open(ciphertext_filename, 'rb') as ct_file, open(new_plaintext_filename, 'wb') as pt_file:
        ...     with aws_encryption_sdk.stream(
        ...         mode='d',
        ...         source=ct_file,
        ...         keyring=keyring,
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
    mode = kwargs.pop("mode")
    _stream_map = {"e": StreamEncryptor, "encrypt": StreamEncryptor, "d": StreamDecryptor, "decrypt": StreamDecryptor}
    try:
        return _stream_map[mode.lower()](**kwargs)
    except KeyError:
        raise ValueError("Unsupported mode: {}".format(mode))
