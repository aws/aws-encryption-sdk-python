"""Singleton provider for the KeyVectors client."""
# # Ignore missing MPL TestVectors for pylint, but the MPL TestVectors is required for this file
# pylint: disable=import-error
from aws_cryptography_materialproviders_test_vectors.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.client import (
        KeyVectors,
    )
from aws_cryptography_materialproviders_test_vectors.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.config import (
        KeyVectorsConfig 
    )

keyvectors_instances = {}


# pylint: disable=too-few-public-methods
class KeyVectorsProvider:
    """Singleton manager for the KeyVectors client."""

    instance: KeyVectors

    @classmethod
    def get_keyvectors(cls, keys_path):
        """Return the singleton KeyVectors client."""
        if keys_path not in keyvectors_instances:
            keyvectors_instances[keys_path] = KeyVectors(KeyVectorsConfig(key_manifest_path=keys_path))
        return keyvectors_instances[keys_path]
