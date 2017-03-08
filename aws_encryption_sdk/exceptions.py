"""Contains exception classes for AWS Encryption SDK."""


class AWSEncryptionSDKClientError(Exception):
    """General exception class for AWS Encryption SDK."""


class SerializationError(AWSEncryptionSDKClientError):
    """Exception class for serialization/deserialization errors."""


class CustomMaximumValueExceeded(SerializationError):
    """Exception class for use when values are found which exceed user-defined custom maximum values."""


class UnknownIdentityError(AWSEncryptionSDKClientError):
    """Exception class for unknown identity errors."""


class NotSupportedError(AWSEncryptionSDKClientError):
    """Exception class for unsupported identities or operations."""


class MasterKeyProviderError(AWSEncryptionSDKClientError):
    """Exception class for Master Key Providers."""


class MasterKeyError(AWSEncryptionSDKClientError):
    """Exception class for Master Keys."""


class InvalidAlgorithmError(AWSEncryptionSDKClientError):
    """Exception class for Invalid Algorithm definitions."""


class InvalidKeyIdError(AWSEncryptionSDKClientError):
    """Exception class for Invalid Key IDs."""


class InvalidDataKeyError(AWSEncryptionSDKClientError):
    """Exception class for Invalid Data Keys."""


class InvalidProviderIdError(AWSEncryptionSDKClientError):
    """Exception class for Invalid Provider IDs."""


class IncorrectMasterKeyError(AWSEncryptionSDKClientError):
    """Exception class for operations attempted against the incorrect Master Key."""


class GenerateKeyError(AWSEncryptionSDKClientError):
    """Exception class for errors encountered when MasterKeys try to generate data keys."""


class EncryptKeyError(AWSEncryptionSDKClientError):
    """Exception class for errors encountered when MasterKeys try to encrypt data keys."""


class DecryptKeyError(AWSEncryptionSDKClientError):
    """Exception class for errors encountered when MasterKeys try to decrypt data keys."""


class ActionNotAllowedError(AWSEncryptionSDKClientError):
    """Exception class for errors encountered when attempting to perform unallowed actions."""


class ConfigMismatchError(AWSEncryptionSDKClientError):
    """Exception class for errors encountered when the wrong type of config is passed to an object."""


class UnknownRegionError(AWSEncryptionSDKClientError):
    """Exception class for errors encountered when attempting to process unknown regions or region names."""
