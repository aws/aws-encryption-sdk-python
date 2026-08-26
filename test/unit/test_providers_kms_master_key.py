# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.key_providers.kms.KMSMasterKey"""
import botocore.client
import pytest
from botocore.exceptions import ClientError
from mock import MagicMock, patch, sentinel

from aws_encryption_sdk.exceptions import DecryptKeyError, EncryptKeyError, GenerateKeyError, MalformedArnError
from aws_encryption_sdk.identifiers import Algorithm
from aws_encryption_sdk.internal.arn import arn_from_str
from aws_encryption_sdk.key_providers.base import MasterKey
from aws_encryption_sdk.key_providers.kms import (
    KMSMasterKey,
    KMSMasterKeyConfig,
    MRKAwareKMSMasterKey,
    MRKAwareKMSMasterKeyConfig,
    _check_mrk_arns_equal,
    _key_resource_match,
)
from aws_encryption_sdk.structures import DataKey, EncryptedDataKey, MasterKeyInfo

from .test_arn import INVALID_KMS_ARNS, INVALID_KMS_IDENTIFIERS, VALID_KMS_IDENTIFIERS
from .test_values import VALUES

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestKMSMasterKey(object):
    @pytest.fixture(autouse=True)
    def apply_fixture(self):
        self.mock_client = MagicMock()
        self.mock_client.__class__ = botocore.client.BaseClient
        self.mock_client.generate_data_key.return_value = {
            "Plaintext": VALUES["data_key"],
            "CiphertextBlob": VALUES["encrypted_data_key"],
            "KeyId": VALUES["arn_str"],
        }
        self.mock_client.encrypt.return_value = {"CiphertextBlob": VALUES["encrypted_data_key"], "KeyId": VALUES["arn"]}
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"], "KeyId": VALUES["arn_str"]}
        self.mock_algorithm = MagicMock()
        self.mock_algorithm.__class__ = Algorithm
        self.mock_algorithm.data_key_len = 32
        self.mock_algorithm.kdf_input_len = sentinel.kdf_input_len
        self.mock_data_key = MagicMock()
        self.mock_data_key.data_key = VALUES["data_key"]
        self.mock_encrypted_data_key = MagicMock()
        self.mock_encrypted_data_key.encrypted_data_key = VALUES["encrypted_data_key"]
        self.mock_encrypted_data_key.key_provider.key_info = VALUES["arn_str"]

        self.mock_data_key_len_check_patcher = patch("aws_encryption_sdk.internal.utils.source_data_key_length_check")
        self.mock_data_key_len_check = self.mock_data_key_len_check_patcher.start()

        self.mock_grant_tokens = (sentinel.grant_token_1, sentinel.grant_token_2)

        self.mrk_region1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd123"
        self.mrk_region2 = "arn:aws:kms:us-west-2:123456789012:key/mrk-abcd123"
        yield
        # Run tearDown
        self.mock_data_key_len_check_patcher.stop()

    def test_kms_parent(self):
        assert issubclass(KMSMasterKey, MasterKey)

    def test_mrkaware_parent(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.5
        # //= type=test
        # //# MUST implement the Master Key Interface (../master-key-
        # //# interface.md#interface)
        assert issubclass(MRKAwareKMSMasterKey, KMSMasterKey)

    @pytest.mark.parametrize("config_class", (KMSMasterKeyConfig, MRKAwareKMSMasterKeyConfig))
    def test_config_bare(self, config_class):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
        # //= type=test
        # //# On initialization, the caller MUST provide:
        test = config_class(key_id=VALUES["arn"], client=self.mock_client)
        assert test.client is self.mock_client
        assert test.grant_tokens == ()

    @pytest.mark.parametrize("config_class", (KMSMasterKeyConfig, MRKAwareKMSMasterKeyConfig))
    def test_config_keyid_required(self, config_class):
        """Fail to instantiate config if missing keyid"""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
        # //= type=test
        # //# The AWS KMS key identifier MUST NOT be null or empty.
        with pytest.raises(TypeError):
            config_class(client=self.mock_client)

    @pytest.mark.parametrize("config_class", (KMSMasterKeyConfig, MRKAwareKMSMasterKeyConfig))
    def test_config_grant_tokens(self, config_class):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
        # //= type=test
        # //# The master key MUST be able to be
        # //# configured with an optional list of Grant Tokens.
        test = config_class(key_id=VALUES["arn"], client=self.mock_client, grant_tokens=self.mock_grant_tokens)
        assert test.grant_tokens is self.mock_grant_tokens

    def test_config_default_client(self):
        """KMSMasterKeys do not require passing a client."""
        test = KMSMasterKeyConfig(key_id=VALUES["arn"])
        arn = arn_from_str(VALUES["arn_str"])
        assert test.client._client_config.region_name == arn.region

    def test_config_no_client_mrkaware(self):
        """MRKAwareKMSMasterKeys require a client."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
        # //= type=test
        # //# The AWS KMS SDK client MUST not be null.
        with pytest.raises(TypeError):
            MRKAwareKMSMasterKeyConfig(key_id=VALUES["arn"])

    @pytest.mark.parametrize(
        "key_id",
        VALID_KMS_IDENTIFIERS
        + INVALID_KMS_IDENTIFIERS,  # To maintain backwards compatibility can be initialized with bad identifiers
    )
    def test_init_kms_master_key(self, key_id):
        self.mock_client.meta.config.user_agent_extra = sentinel.user_agent_extra
        config = KMSMasterKeyConfig(key_id=key_id, client=self.mock_client)
        test = KMSMasterKey(config=config)
        assert test._key_id == key_id

    @pytest.mark.parametrize(
        "key_id",
        VALID_KMS_IDENTIFIERS,
    )
    def test_init_mrk_kms_master_key(self, key_id):
        self.mock_client.meta.config.user_agent_extra = sentinel.user_agent_extra
        config = MRKAwareKMSMasterKeyConfig(key_id=key_id, client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)
        assert test._key_id == key_id

    @pytest.mark.parametrize(
        "key_id",
        INVALID_KMS_IDENTIFIERS,
    )
    def test_init_mrk_kms_master_key_invalid_id(self, key_id):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
        # //= type=test
        # //# The AWS KMS
        # //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
        # //# valid-aws-kms-identifier).
        self.mock_client.meta.config.user_agent_extra = sentinel.user_agent_extra
        config = MRKAwareKMSMasterKeyConfig(key_id=key_id, client=self.mock_client)
        with pytest.raises(MalformedArnError) as excinfo:
            MRKAwareKMSMasterKey(config=config)
        excinfo.match("Resource {key} could not be parsed as an ARN".format(key=key_id))

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_generate_data_key(self, config_class, key_class, key_id):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //= type=test
        # //# The inputs MUST be the same as the Master Key Generate Data Key
        # //# (../master-key-interface.md#generate-data-key) interface.
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        generated_key = test._generate_data_key(self.mock_algorithm)
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //= type=test
        # //# This master key MUST use the configured AWS KMS client to make an AWS KMS
        # //# GenerateDatakey (https://docs.aws.amazon.com/kms/latest/APIReference/
        # //# API_GenerateDataKey.html) request constructed as follows:
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=key_id.decode("ascii"), NumberOfBytes=sentinel.kdf_input_len
        )

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //= type=test
        # //# The output MUST be the same as the Master Key Generate Data Key
        # //# (../master-key-interface.md#generate-data-key) interface.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //= type=test
        # //# The response's cipher text blob MUST be used as the returned as the
        # //# ciphertext for the encrypted data key in the output.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //= type=test
        # //# The response's "Plaintext" MUST be the plaintext in the output.
        assert generated_key == DataKey(
            key_provider=MasterKeyInfo(provider_id=test.provider_id, key_info=VALUES["arn"]),
            data_key=VALUES["data_key"],
            encrypted_data_key=VALUES["encrypted_data_key"],
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_generate_data_key_with_encryption_context(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        test._generate_data_key(self.mock_algorithm, VALUES["encryption_context"])
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=key_id.decode("ascii"),
            NumberOfBytes=sentinel.kdf_input_len,
            EncryptionContext=VALUES["encryption_context"],
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_generate_data_key_with_grant_tokens(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client, grant_tokens=self.mock_grant_tokens)
        test = key_class(config=config)
        test._generate_data_key(self.mock_algorithm)
        self.mock_client.generate_data_key.assert_called_once_with(
            KeyId=key_id.decode("ascii"), NumberOfBytes=sentinel.kdf_input_len, GrantTokens=self.mock_grant_tokens
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_generate_data_key_unsuccessful_clienterror(self, config_class, key_class, key_id):
        self.mock_client.generate_data_key.side_effect = ClientError({"Error": {}}, "This is an error!")
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        with pytest.raises(GenerateKeyError) as excinfo:
            test._generate_data_key(self.mock_algorithm)
        excinfo.match("Master Key .* unable to generate data key")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_generate_data_key_unsuccessful_keyerror(self, config_class, key_class, key_id):
        self.mock_client.generate_data_key.side_effect = KeyError
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        with pytest.raises(GenerateKeyError) as excinfo:
            test._generate_data_key(self.mock_algorithm)
        excinfo.match("Master Key .* unable to generate data key")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_generate_data_key_unsuccessful_response_invalid_key_id(self, config_class, key_class, key_id):
        """Check that we fail if KMS returns a response with an invalid keyid."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
        # //= type=test
        # //# The response's "KeyId" MUST be valid.
        invalid_key_id = "Not:an/arn"
        self.mock_client.generate_data_key.return_value = {
            "Plaintext": VALUES["data_key"],
            "CiphertextBlob": VALUES["encrypted_data_key"],
            "KeyId": invalid_key_id,
        }

        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id

        with pytest.raises(GenerateKeyError) as excinfo:
            test._generate_data_key(algorithm=self.mock_algorithm)
        excinfo.match("Retrieved an unexpected KeyID in response from KMS")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_encrypt_data_key(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_client.encrypt.return_value["KeyId"] = key_id
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //= type=test
        # //# The inputs MUST be the same as the Master Key Encrypt Data Key
        # //# (../master-key-interface.md#encrypt-data-key) interface.
        encrypted_key = test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //= type=test
        # //# The master key MUST use the configured AWS KMS client to make an AWS KMS Encrypt
        # //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        # //# API_Encrypt.html) request constructed as follows:
        self.mock_client.encrypt.assert_called_once_with(KeyId=key_id.decode("ascii"), Plaintext=VALUES["data_key"])

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //= type=test
        # //# The response's cipher text blob MUST be used as the "ciphertext" for the
        # //# encrypted data key.

        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //= type=test
        # //# The output MUST be the same as the Master Key Encrypt Data Key
        # //# (../master-key-interface.md#encrypt-data-key) interface.
        assert encrypted_key == EncryptedDataKey(
            key_provider=MasterKeyInfo(provider_id=test.provider_id, key_info=key_id.decode("ascii")),
            encrypted_data_key=VALUES["encrypted_data_key"],
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_encrypt_data_key_with_encryption_context(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_client.encrypt.return_value["KeyId"] = key_id
        test._encrypt_data_key(self.mock_data_key, self.mock_algorithm, VALUES["encryption_context"])
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=key_id.decode("ascii"), Plaintext=VALUES["data_key"], EncryptionContext=VALUES["encryption_context"]
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_encrypt_data_key_with_grant_tokens(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client, grant_tokens=self.mock_grant_tokens)
        test = key_class(config=config)
        self.mock_client.encrypt.return_value["KeyId"] = key_id
        test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        self.mock_client.encrypt.assert_called_once_with(
            KeyId=key_id.decode("ascii"), Plaintext=VALUES["data_key"], GrantTokens=self.mock_grant_tokens
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_encrypt_data_key_unsuccessful_clienterror(self, config_class, key_class, key_id):
        self.mock_client.encrypt.side_effect = ClientError({"Error": {}}, "This is an error!")
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        with pytest.raises(EncryptKeyError) as excinfo:
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        excinfo.match("Master Key .* unable to encrypt data key")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_encrypt_data_key_unsuccessful_keyerror(self, config_class, key_class, key_id):
        self.mock_client.encrypt.side_effect = KeyError
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        with pytest.raises(EncryptKeyError) as excinfo:
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        excinfo.match("Master Key .* unable to encrypt data key")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_encrypt_data_key_unsuccessful_response_invalid_key_id(self, config_class, key_class, key_id):
        """Check that we fail if KMS returns a response with an invalid keyid."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
        # //= type=test
        # //# The AWS KMS Encrypt response MUST contain a valid "KeyId".
        invalid_key_id = "Not:an/arn"
        self.mock_client.encrypt.return_value = {
            "Plaintext": VALUES["data_key"],
            "CiphertextBlob": VALUES["encrypted_data_key"],
            "KeyId": invalid_key_id,
        }

        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id

        with pytest.raises(EncryptKeyError) as excinfo:
            test._encrypt_data_key(self.mock_data_key, self.mock_algorithm)
        excinfo.match("Retrieved an unexpected KeyID in response from KMS")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id.decode("ascii")
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# The inputs MUST be the same as the Master Key Decrypt Data Key
        # //# (../master-key-interface.md#decrypt-data-key) interface.
        decrypted_key = test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm
        )
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# To decrypt the encrypted data key this master key MUST use the
        # //# configured AWS KMS client to make an AWS KMS Decrypt
        # //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        # //# API_Decrypt.html) request constructed as follows:
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"], KeyId=key_id.decode("ascii")
        )
        assert decrypted_key == DataKey(
            key_provider=test.key_provider, data_key=VALUES["data_key"], encrypted_data_key=VALUES["encrypted_data_key"]
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", INVALID_KMS_ARNS)
    def test_decrypt_data_key_invalid_arn_edk(self, config_class, key_class, key_id):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# Additionally each provider info MUST be a valid AWS KMS ARN
        # //# (aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of
        # //# "key".
        config = config_class(key_id=VALUES["arn"], client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id
        with pytest.raises(MalformedArnError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("Resource {key_id} could not be parsed as an ARN".format(key_id=key_id))

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    def test_decrypt_data_key_alias_arn_edk(self, config_class, key_class):
        key_id = "arn:aws:kms:us-east-1:248168362296:alias/myAlias"
        config = config_class(key_id=VALUES["arn"], client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("AWS KMS Provider EDK contains unexpected key_id: {key_id}".format(key_id=key_id))

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_with_encryption_context(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id.decode("ascii")
        test._decrypt_data_key(
            encrypted_data_key=self.mock_encrypted_data_key,
            algorithm=self.mock_algorithm,
            encryption_context=VALUES["encryption_context"],
        )
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"],
            EncryptionContext=VALUES["encryption_context"],
            KeyId=key_id.decode("ascii"),
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_with_grant_tokens(self, config_class, key_class, key_id):
        config = config_class(key_id=key_id, client=self.mock_client, grant_tokens=self.mock_grant_tokens)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id.decode("ascii")
        test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"],
            GrantTokens=self.mock_grant_tokens,
            KeyId=key_id.decode("ascii"),
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_unsuccessful_clienterror(self, config_class, key_class, key_id):
        self.mock_client.decrypt.side_effect = ClientError({"Error": {}}, "This is an error!")
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id.decode("ascii")
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("Master Key .* unable to decrypt data key")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_unsuccessful_keyerror(self, config_class, key_class, key_id):
        self.mock_client.decrypt.side_effect = KeyError
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id.decode("ascii")
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("Master Key .* unable to decrypt data key")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_unsuccessful_response_missing_key_id(self, config_class, key_class, key_id):
        """Check that we fail if KMS returns a response without a keyid."""
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"]}

        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# If all the input encrypted data keys have been processed then this
        # //# function MUST yield an error that includes all the collected errors.
        # Note the latter half of "includes all collected errors" is not satisfied
        excinfo.match("Master Key .* unable to decrypt data key")

        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"], KeyId=key_id.decode("ascii")
        )

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_unsuccessful_incorrect_plaintext_length(self, config_class, key_class, key_id):
        """Check that we fail if KMS returns a plaintext of an unexpected length."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# The response's "Plaintext"'s length MUST equal the length
        # //# required by the requested algorithm suite otherwise the function MUST
        # //# collect an error.
        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_algorithm.data_key_len = 128
        self.mock_encrypted_data_key.key_provider.key_info = key_id
        self.mock_client.decrypt.return_value["KeyId"] = key_id.decode("ascii")

        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("Plaintext length .* does not match algorithm's expected length")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_unsuccessful_mismatched_key_id(self, config_class, key_class, key_id):
        """For all keys, if KMS returns a completely different key id we should fail to decrypt."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# If the call succeeds then the response's "KeyId" MUST be equal to the
        # //# configured AWS KMS key identifier otherwise the function MUST collect
        # //# an error.
        mismatched_key_id = key_id.decode("ascii") + "-test"
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"], "KeyId": mismatched_key_id}

        config = config_class(key_id=key_id, client=self.mock_client)
        test = key_class(config=config)
        self.mock_encrypted_data_key.key_provider.key_info = key_id

        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("AWS KMS returned unexpected key_id")

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    @pytest.mark.parametrize("key_id", [VALUES["mrk_arn_region1"], VALUES["arn"]])
    def test_decrypt_data_key_unsuccessful_key_id_does_not_match_edk(self, config_class, key_class, key_id):
        """For all keys, if the configured key id is a complete mismatch from the EDK key, we should fail to decrypt."""
        mismatched_key_id = key_id.decode("ascii") + "-test"
        config = config_class(key_id=mismatched_key_id, client=self.mock_client)
        test = key_class(config=config)
        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("does not match this provider's key_id")

        self.mock_client.assert_not_called()

    @pytest.mark.parametrize(
        "config_class, key_class",
        [(KMSMasterKeyConfig, KMSMasterKey), (MRKAwareKMSMasterKeyConfig, MRKAwareKMSMasterKey)],
    )
    def test_decrypt_data_key_unsuccessful_srks_different_region(self, config_class, key_class):
        """For SRKs, if the configured key id is identical to the EDK key except for region, no provider should treat
        them as equivalent (since they are SRKs). This is a slightly more specific case than the general "mismatched
        key id" in a previous test.

        Note that the chances of having two identical SRK key ids from different regions is tiny, but we should handle
        the case anyway."""
        key_id1 = VALUES["arn"]
        arn = arn_from_str(VALUES["arn_str"])
        arn.region = "ap-southeast-1"
        key_id2 = arn.to_string()

        # Config uses the first SRK
        config = config_class(key_id=key_id1, client=self.mock_client)
        test = key_class(config=config)

        # EDK contains the second SRK
        self.mock_encrypted_data_key.key_provider.key_info = key_id2

        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("Cannot decrypt EDK wrapped by .*, because it does not match this provider")

    def test_decrypt_data_key_successful_mrk_provider_different_regions(self):
        """For MRK-aware key providers, we should successfully decrypt using a related MRK."""
        # Config and KMS use the MRK in region 1
        config = MRKAwareKMSMasterKeyConfig(key_id=VALUES["mrk_arn_region1"], client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)
        self.mock_client.decrypt.return_value = {
            "Plaintext": VALUES["data_key"],
            "KeyId": VALUES["mrk_arn_region1_str"],
        }

        # EDK contains the related MRK in region 2
        self.mock_encrypted_data_key.key_provider.key_info = VALUES["mrk_arn_region2"]

        test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        self.mock_client.decrypt.assert_called_once_with(
            CiphertextBlob=VALUES["encrypted_data_key"], KeyId=VALUES["mrk_arn_region1_str"]
        )

    def test_decrypt_data_key_unsuccessful_non_mrk_provider_different_region(self):
        """For non MRK-aware key providers, related MRKs are not treated as equivalent and decryption should fail."""
        # Config uses the MRK in region 1
        config = KMSMasterKeyConfig(key_id=VALUES["mrk_arn_region1"], client=self.mock_client)
        test = KMSMasterKey(config=config)

        # EDK contains the related MRK in region 2
        self.mock_encrypted_data_key.key_provider.key_info = VALUES["mrk_arn_region2"]

        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=self.mock_algorithm)
        excinfo.match("Cannot decrypt EDK wrapped by .*, because it does not match this provider")

    def test_decrypt_data_key_failure_kms_returns_wrong_mrk(self):
        """For an MRK-aware provider, if KMS returns the MRK from the EDK rather than the MRK we called it with,
        we should fail."""
        # Config uses MRK for region 1
        config = MRKAwareKMSMasterKeyConfig(key_id=self.mrk_region1, client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)

        # KMS returns the MRK for region 2
        self.mock_client.decrypt.return_value = {"Plaintext": VALUES["data_key"], "KeyId": self.mrk_region2}
        self.mock_encrypted_data_key.key_provider.key_info = self.mrk_region2

        with pytest.raises(DecryptKeyError) as excinfo:
            test._decrypt_data_key(encrypted_data_key=self.mock_encrypted_data_key, algorithm=sentinel.algorithm)
        excinfo.match("AWS KMS returned unexpected key_id")

    def test_owns_data_key_owned_same_region(self):
        """The MRK Aware Master Key owns a data key when the arn exactly matches its configured ARN."""
        config = MRKAwareKMSMasterKeyConfig(key_id=self.mrk_region1, client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)
        mock_data_key = MagicMock()
        mock_data_key.key_provider = MagicMock()
        mock_data_key.key_provider.provider_id = "aws-kms"
        mock_data_key.key_provider.key_info = self.mrk_region1
        assert test.owns_data_key(data_key=mock_data_key)

    def test_owns_data_key_owned_different_region(self):
        """The MRK Aware Master Key owns a data key when the arn refers to a related MRK of its configured ARN."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
        # //= type=test
        # //# To match the encrypted data key's
        # //# provider ID MUST exactly match the value "aws-kms" and the the
        # //# function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-for-
        # //# decrypt.md#implementation) called with the configured AWS KMS key
        # //# identifier and the encrypted data key's provider info MUST return
        # //# "true".
        config = MRKAwareKMSMasterKeyConfig(key_id=self.mrk_region1, client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)
        mock_data_key = MagicMock()
        mock_data_key.key_provider = MagicMock()
        mock_data_key.key_provider.provider_id = "aws-kms"
        mock_data_key.key_provider.key_info = self.mrk_region2
        assert test.owns_data_key(data_key=mock_data_key)

    def test_owns_data_key_not_owned_wrong_provider(self):
        """The MRK Aware Master Key does not own a data key when the provider doesn't match."""
        config = MRKAwareKMSMasterKeyConfig(key_id=self.mrk_region1, client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)
        mock_data_key = MagicMock()
        mock_data_key.key_provider = MagicMock()
        mock_data_key.key_provider.provider_id = "another_provider"
        mock_data_key.key_provider.key_info = self.mrk_region1
        assert not test.owns_data_key(data_key=mock_data_key)

    def test_owns_data_key_not_owned_wrong_key_id(self):
        """The MRK Aware Master Key does not own a data key when the key arn is not a related MRK of its
        configured ARN."""
        config = MRKAwareKMSMasterKeyConfig(key_id=self.mrk_region1, client=self.mock_client)
        test = MRKAwareKMSMasterKey(config=config)
        mock_data_key = MagicMock()
        mock_data_key.key_provider = MagicMock()
        mock_data_key.key_provider.provider_id = "aws-kms"
        mock_data_key.key_provider.key_info = VALUES["arn"]
        assert not test.owns_data_key(data_key=mock_data_key)

    def test_match_srks_strictly_equal(self):
        key1 = "arn:aws:kms:us-east-1:123456789012:key/abcd123"
        assert _check_mrk_arns_equal(key1, key1)

    def test_match_mrks_strictly_equal(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        # //= type=test
        # //# If both identifiers are identical, this function MUST return "true".
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd123"
        assert _check_mrk_arns_equal(key1, key1)

    def test_match_mrk_to_srk(self):
        key1 = "arn:aws:kms:us-east-1:123456789012:key/abcd123"
        mrk1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd123"
        assert not _check_mrk_arns_equal(key1, mrk1)
        assert not _check_mrk_arns_equal(mrk1, key1)

    def test_match_mrks_srks(self):
        """Single-Region keys cannot be equivalent MRKs, even if all fields (except region) match."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        # //= type=test
        # //# Otherwise if either input is not identified as a multi-Region key
        # //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
        # //# this function MUST return "false".
        key1 = "arn:aws:kms:us-east-1:123456789012:key/abcd123"
        key2 = "arn:aws:kms:us-west-2:123456789012:key/abcd123"
        assert not _check_mrk_arns_equal(key1, key2)

    def test_match_mrks(self):
        """Multi-Region keys are equivalent if all fields except region match."""
        # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        # //= type=test
        # //# Otherwise if both inputs are
        # //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
        # //# aws-kms-multi-region-key), this function MUST return the result of
        # //# comparing the "partition", "service", "accountId", "resourceType",
        # //# and "resource" parts of both ARN inputs.

        # //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
        # //= type=test
        # //# The caller MUST provide:
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd123"
        key2 = "arn:aws:kms:us-west-2:123456789012:key/mrk-abcd123"
        assert _check_mrk_arns_equal(key1, key2)

    def test_master_keys_for_encryption_not_overridden(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.7
        # //= type=test
        # //# MUST be unchanged from the Master Key interface.
        assert MRKAwareKMSMasterKey.master_keys_for_encryption == KMSMasterKey.master_keys_for_encryption

    def test_master_key_not_overridden(self):
        # //= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.8
        # //= type=test
        # //# MUST be unchanged from the Master Key interface.
        assert MRKAwareKMSMasterKey.master_key == KMSMasterKey.master_key

    def test_match_mrks_wrong_partition(self):
        """Multi-Region keys are not equivalent if the partition does not match."""
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd123"
        key2 = "arn:aws-us-gov:kms:us-west-2:123456789012:key/mrk-abcd123"
        assert not _check_mrk_arns_equal(key1, key2)
        assert not _check_mrk_arns_equal(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_match_mrks_wrong_account(self):
        """Multi-Region keys are not equivalent if the account does not match."""
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd123"
        key2 = "arn:aws:kms:us-west-2:333333333333:key/mrk-abcd123"
        assert not _check_mrk_arns_equal(key1, key2)
        assert not _check_mrk_arns_equal(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_match_mrks_wrong_resource_id(self):
        """Multi-Region keys are not equivalent if the resource id does not match."""
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-123"
        key2 = "arn:aws:kms:us-west-2:123456789012:key/mrk-abc"
        assert not _check_mrk_arns_equal(key1, key2)
        assert not _check_mrk_arns_equal(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_match_mrks_bare_key_id_and_arn(self):
        """For matching on decrypt, we cannot compare ARNs to bare key ids."""
        key1 = "mrk-123"
        key2 = "arn:aws:kms:us-west-2:123456789012:key/mrk-123"
        with pytest.raises(MalformedArnError) as excinfo:
            _check_mrk_arns_equal(key1, key2)
        excinfo.match("Resource .+ could not be parsed as an ARN")

    def test_related_mrks_bare_key_ids(self):
        """When checking uniqueness, bare key ids are equivalent if they are the same."""
        key1 = "mrk-123"
        key2 = "mrk-123"
        assert _check_mrk_arns_equal(key1, key2)
        assert _check_mrk_arns_equal(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_key_resource_match_same_arn_resource_id(self):
        """When checking resource ids, arns match if they have the same resource id"""
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-123"
        key2 = "arn:not-aws:kms:us-west-2:000000000000:key/mrk-123"
        assert _key_resource_match(key1, key2)
        assert _key_resource_match(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_key_resource_match_arn_and_bare_id(self):
        """When checking resource ids, an arn matches a bare id if the bare id equals its resource id"""
        key1 = "mrk-123"
        key2 = "arn:aws:kms:us-west-2:123456789012:key/mrk-123"
        assert _key_resource_match(key1, key2)
        assert _key_resource_match(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_key_resource_match_bare_ids(self):
        """When checking resource ids, bare ids match if they are the same"""
        key1 = "mrk-123"
        assert _key_resource_match(key1, key1)

    def test_key_resource_match_different_resource_ids(self):
        """When checking resource ids, arns do not match if they have different resource ids"""
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-123"
        key2 = "arn:aws:kms:us-west-2:123456789012:key/mrk-abc"
        assert not _key_resource_match(key1, key2)
        assert not _key_resource_match(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_key_resource_match_alias_resource_type(self):
        """When checking resource ids, arns do not match if one is an alias resource type"""
        key1 = "arn:aws:kms:us-east-1:123456789012:key/mrk-123"
        key2 = "arn:aws:kms:us-east-1:123456789012:alias/mrk-123"
        assert not _key_resource_match(key1, key2)
        assert not _key_resource_match(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_key_resource_match_bare_id_with_alias_resource_type(self):
        """When checking resource ids, arns do not match if one is an alias resource type and the other is a bare id"""
        key1 = "mrk-123"
        key2 = "arn:aws:kms:us-east-1:123456789012:alias/mrk-123"
        assert not _key_resource_match(key1, key2)
        assert not _key_resource_match(key2, key1)  # pylint: disable=arguments-out-of-order

    def test_key_resource_match_different_bare_ids(self):
        """When checking resource ids, bare ids do not match if they are different"""
        key1 = "mrk-123"
        key2 = "mrk-abc"
        assert not _key_resource_match(key1, key2)
        assert not _key_resource_match(key2, key1)  # pylint: disable=arguments-out-of-order
