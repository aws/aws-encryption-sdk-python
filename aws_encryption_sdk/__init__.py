"""High level AWS Encryption SDK client functions."""
from aws_encryption_sdk.streaming_client import StreamEncryptor, StreamDecryptor, EncryptorConfig, DecryptorConfig
# Below are imported for ease of use by implementors
from aws_encryption_sdk.identifiers import Algorithm, __version__
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider, KMSMasterKeyProviderConfig


def encrypt(**kwargs):
    """Encrypts and serializes provided plaintext.

    .. note::
        When using this function, the entire ciphertext message is encrypted into memory before returning
        any data.  If streaming is desired, see :class:`aws_encryption_sdk.stream`.

    .. code:: python

        >>> import aws_encryption_sdk
        >>> kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
        ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
        ... ])
        >>> my_ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
        ...     source=my_plaintext,
        ...     key_provider=kms_key_provider
        ... )

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.EncryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for encryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and unframed message is being written or read() is called,
            will attempt to seek() to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    :param dict encryption_context: Dictionary defining encryption context
    :param algorithm: Algorithm to use for encryption
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param int frame_length: Frame length in bytes
    :returns: Tuple containing the encrypted ciphertext and the message header object
    :rtype: tuple of str and :class:`aws_encryption_sdk.structure.MessageHeader`
    """
    with StreamEncryptor(**kwargs) as encryptor:
        ciphertext = encryptor.read()
    return ciphertext, encryptor.header


def decrypt(**kwargs):
    """Deserializes and decrypts provided ciphertext.

    .. note::
        When using this function, the entire ciphertext message is decrypted into memory before returning
        any data.  If streaming is desired, see :class:`aws_encryption_sdk.stream`.

    .. code:: python

        >>> import aws_encryption_sdk
        >>> kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
        ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
        ... ])
        >>> my_ciphertext, encryptor_header = aws_encryption_sdk.decrypt(
        ...     source=my_ciphertext,
        ...     key_provider=kms_key_provider
        ... )

    :param config: Client configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.streaming_client.DecryptorConfig
    :param source: Source data to encrypt or decrypt
    :type source: str, bytes, io.IOBase, or file
    :param key_provider: MasterKeyProvider from which to obtain data keys for decryption
    :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param int source_length: Length of source data (optional)

        .. note::
            If source_length is not provided and read() is called, will attempt to seek()
            to the end of the stream and tell() to find the length of source data.
    :param int line_length: Line length to use for reading "lines" from stream (optional)

        .. note::
            The concept of "lines" is used to match Python file-like-object terminology.  In this
            context it defines the number of bytes returned by readline().
    :param int max_body_length: Maximum frame size (or content length for non-framed messages)
    in bytes to read from ciphertext message.
    :returns: Tuple containing the decrypted plaintext and the message header object
    :rtype: tuple of str and :class:`aws_encryption_sdk.structure.MessageHeader`
    """
    with StreamDecryptor(**kwargs) as decryptor:
        plaintext = decryptor.read()
    return plaintext, decryptor.header


def stream(**kwargs):
    """Provides an :py:func:`open`-like interface to the streaming encryptor/decryptor classes.

    .. note::
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
        >>> kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
        ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
        ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
        ...  ])
        >>> plaintext_filename = 'my-secret-data.dat'
        >>> ciphertext_filename = 'my-encrypted-data.ct'
        >>> with open(plaintext_filename, 'rb') as pt_file, open(ciphertext_filename, 'wb') as ct_file:
        ...      with aws_encryption_sdk.stream(
        ...         mode='e',
        ...         source=pt_file,
        ...         key_provider=kms_key_provider
        ...     ) as encryptor:
        ...         for chunk in encryptor:
        ...              ct_file.write(chunk)
        >>> new_plaintext_filename = 'my-decrypted-data.dat'
        >>> with open(ciphertext_filename, 'rb') as ct_file, open(new_plaintext_filename, 'wb') as pt_file:
        ...     with aws_encryption_sdk.stream(
        ...         mode='d',
        ...         source=ct_file,
        ...         key_provider=kms_key_provider
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
    mode = kwargs.pop('mode')
    _stream_map = {
        'e': StreamEncryptor,
        'encrypt': StreamEncryptor,
        'd': StreamDecryptor,
        'decrypt': StreamDecryptor
    }
    try:
        return _stream_map[mode.lower()](**kwargs)
    except KeyError:
        raise ValueError('Unsupported mode: {}'.format(mode))

__all__ = (
    'encrypt',
    'decrypt',
    'stream'
)
