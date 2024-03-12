from aws_cryptography_materialproviderstestvectorkeys.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.client import (
        KeyVectors,
    )
from aws_cryptography_materialproviderstestvectorkeys.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.config import (
        KeyVectorsConfig
    )

keyvectors_instances = {}

class KeyVectorsProvider:
    """Singleton manager for the KeyVectors client.
    
    This is used because Dafny's JSON deserializer implementation is slow with large files.
    It deserializes the file at keys_path and takes >1 minute to do this.
    """

    instance: KeyVectors

    @classmethod
    def get_keyvectors(self, keys_path):
        if not keys_path in keyvectors_instances:
            keyvectors_instances[keys_path] = KeyVectors(KeyVectorsConfig(key_manifest_path=keys_path))
        return keyvectors_instances[keys_path]
