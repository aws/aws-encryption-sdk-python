# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Keyring Manifest handler.

This REQUIRES the aws-cryptographic-material-providers library.
"""
import attr

from aws_cryptography_materialproviderstestvectorkeys.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.models import (
        GetKeyDescriptionInput,
        GetKeyDescriptionOutput,
        TestVectorKeyringInput,
    )
from aws_cryptography_materialproviderstestvectorkeys.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.client import (
        KeyVectors,
    )
from aws_cryptography_materialproviderstestvectorkeys.smithygenerated.\
    aws_cryptography_materialproviderstestvectorkeys.config import (
        KeyVectorsConfig
    )
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from aws_cryptographic_materialproviders.mpl.models import CreateMultiKeyringInput

from awses_test_vectors.manifests.keys import KeysManifest  # noqa pylint disable=unused-import

import json

from .master_key import MasterKeySpec


@attr.s
class KeyringSpec(MasterKeySpec):  # pylint: disable=too-many-instance-attributes
    """AWS Encryption SDK master key specification utilities.

    Described in AWS Crypto Tools Test Vector Framework features #0003 and #0004.

    :param str type_name: Master key type name
    :param str key_name: Name of key in keys spec
    :param str provider_id: Master key provider ID
    :param str encryption_algorithm: Wrapping key encryption algorithm (required for raw master keys)
    :param str padding_algorithm: Wrapping key padding algorithm (required for raw master keys)
    :param str padding_hash: Wrapping key padding hash (required for raw master keys)
    """

    def keyring(self, keys_uri):
        # type: (KeysManifest) -> IKeyring
        """Build a keyring using this specification.

        :param str keys_uri: Path to the keys manifest
        """

        keyvectors = KeyVectors(KeyVectorsConfig(key_manifest_path=keys_uri))

        # Construct the input to KeyVectorsConfig
        input_as_dict = {
            "type": self.type_name,
            "key": self.key_name,
            "provider-id": self.provider_id,
            "encryption-algorithm": self.encryption_algorithm,
            "padding-algorithm": self.padding_algorithm,
            "padding-hash": self.padding_hash
        }
        # stringify the dict
        input_as_string = json.dumps(input_as_dict)
        # convert to unicode code point (expected representation)
        encoded_json = [ord(c) for c in input_as_string]

        output: GetKeyDescriptionOutput = keyvectors.get_key_description(
            GetKeyDescriptionInput(json=encoded_json)
        )

        keyring: IKeyring = keyvectors.create_test_vector_keyring(
            TestVectorKeyringInput(
                key_description=output.key_description
            )
        )

        return keyring


def keyring_from_master_key_specs(keys_uri, master_key_specs):
    # type: (str, list[KeyringSpec]) -> IKeyring
    """Build and combine all keyrings identified by the provided specs and
    using the provided keys.

    :param str keys_uri: Path to the keys manifest
    :param master_key_specs: Master key specs from which to load master keys
    :type master_key_specs: iterable of MasterKeySpec
    :return: Master key provider combining all loaded master keys
    :rtype: IKeyring
    """
    keyrings = [spec.keyring(keys_uri) for spec in master_key_specs]
    primary = keyrings[0]
    others = keyrings[1:]

    mpl: AwsCryptographicMaterialProviders = AwsCryptographicMaterialProviders(
        MaterialProvidersConfig()
    )
    multi_keyring: IKeyring = mpl.create_multi_keyring(
        CreateMultiKeyringInput(
            generator=primary,
            child_keyrings=others
        )
    )
    return multi_keyring
