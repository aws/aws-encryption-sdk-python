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
from aws_cryptographic_materialproviders.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_materialproviders.mpl.config import MaterialProvidersConfig
from aws_cryptographic_materialproviders.mpl.references import IKeyring
from aws_cryptographic_materialproviders.mpl.models import CreateMultiKeyringInput

from awses_test_vectors.internal.keyvectors_provider import KeyVectorsProvider
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

    def keyring(self, keys, keys_uri, mode):
        # type: (KeysManifest) -> IKeyring
        """Build a keyring using this specification.

        :param str keys_uri: Path to the keys manifest
        """

        '''
        encryptmaterials keyProviderInfo = rsa-4096-public'
        MUST be private.
        somehow, it is writing "rsa-4096-public".
        
        '''

        print(f"{keys=}")

        keyvectors = KeyVectorsProvider.get_keyvectors(keys_path=keys_uri)

        changed = False

        # Construct the input to KeyVectorsConfig
        input_kwargs = {
            "type": self.type_name,
            "key": self.key_name,
            "provider-id": self.provider_id,
            "encryption-algorithm": self.encryption_algorithm,
            
        }
        if self.padding_algorithm is not None and self.padding_algorithm != "":
            input_kwargs["padding-algorithm"] = self.padding_algorithm
        if self.padding_hash is not None:
            input_kwargs["padding-hash"] = self.padding_hash

        if input_kwargs["type"] == "raw" \
                and input_kwargs["encryption-algorithm"] == "rsa":
            # Weird hack #1:
            # Gets public key for encryption instead of private key.
            # 
            # If generating decrypt vectors (i.e. encrypting)
            # and the manifest specified an RSA private key,
            # change the input to KeyVectors to a public key.
            # KeyVectors requires a public key to encrypt.
            # If this is not done, then keyring.OnEncrypt fails with
            # "A RawRSAKeyring without a public key cannot provide OnEncrypt"
            if input_kwargs["key"] == "rsa-4096-private" \
                and (mode == "decrypt-generate" or mode == "encrypt"):
                changed = True
                input_kwargs["key"] = "rsa-4096-public"
            # Specify default padding-hash
            if "padding-hash" not in input_kwargs:
                input_kwargs["padding-hash"] = "sha1"

        # stringify the dict
        input_as_string = json.dumps(input_kwargs)
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

        # Weird hack #2:
        # Sets keyProviderInfo to "private" even though the material is "public".
        # 
        # Weird hack #1 allows the encrypting keyring to be created with a public key.
        # However, it also changes the keyName of the encrypting keyring.
        # This hack changes it back.
        # 
        # If this is not done, then decryption fails
        # (for BOTH native master keys and MPL keyrings)
        # with error 
        # native master keys: "Unable to decrypt any data key"
        # MPL: "Raw RSA Key was unable to decrypt any encrypted data key"
        # 
        # Digging, the keyring is unable to decrypt in the MPL
        # because the EDK keyProviderInfo differs from the keyring keyName,
        # and this check fails:
        # https://github.com/aws/aws-cryptographic-material-providers-library/blob/bd549c88cefc93ba8a2d204bd23134b3b12c69fb/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/RawRSAKeyring.dfy#L382
        # due to the two variables not being equal:
        # edk.keyProviderInfo='rsa-4096-public'
        # keyring.keyName='rsa-4096-private'
        # 
        # Changing the encrypting keyring's keyName back to 'rsa-4096-private' 
        # sets any EDKs this keyring encrypts to now have 
        # keyName="rsa-4096-private".
        # However, keyvectors has still retrieved the public key material to encrypt with.
        # So it any EDKs it encrypts will use the public material, but have keyName="rsa-4096-private".
        # 
        # This configuration seems to be correct, because 
        # all of the test vectors (master keys and MPL) pass with these two hacks.
        # But this seems weird, and we didn't have to do this in Java.
        import _dafny
        import UTF8

        if hasattr(keyring, "_impl"):
            if hasattr(keyring._impl, "_keyName"):
                if keyring._impl._keyName == UTF8.default__.Encode(_dafny.Seq("rsa-4096-public")).value \
                        and (mode == "decrypt-generate" or mode == "encrypt"):
                        if changed:
                            keyring._impl._keyName = UTF8.default__.Encode(_dafny.Seq("rsa-4096-private")).value

        return keyring


def keyring_from_master_key_specs(keys, keys_uri, master_key_specs, mode):
    # type: (str, list[KeyringSpec]) -> IKeyring
    """Build and combine all keyrings identified by the provided specs and
    using the provided keys.

    :param str keys_uri: Path to the keys manifest
    :param master_key_specs: Master key specs from which to load master keys
    :type master_key_specs: iterable of MasterKeySpec
    :return: Master key provider combining all loaded master keys
    :rtype: IKeyring
    """
    keyrings = [spec.keyring(keys, keys_uri, mode) for spec in master_key_specs]
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
