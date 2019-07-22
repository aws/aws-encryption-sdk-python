# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Functional tests for Raw AES keyring encryption decryption path."""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_encryption_sdk.identifiers import Algorithm, KeyringTraceFlag, WrappingAlgorithm
from aws_encryption_sdk.keyring.raw_keyring import RawRSAKeyring
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials
from aws_encryption_sdk.structures import EncryptedDataKey, KeyringTrace, MasterKeyInfo, RawDataKey

pytestmark = [pytest.mark.functional, pytest.mark.local]

_ENCRYPTION_CONTEXT = {"encryption": "context", "values": "here"}
_PROVIDER_ID = "Random Raw Keys"
_KEY_ID = b"5325b043-5843-4629-869c-64794af77ada"
_SIGNING_KEY = b"aws-crypto-public-key"
_WRAPPING_ALGORITHM = WrappingAlgorithm.RSA_OAEP_SHA256_MGF1

_ENCRYPTION_MATERIALS = [
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
    ),
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY},
            )
        ],
    ),
    EncryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        data_encryption_key=RawDataKey(
            key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
            data_key=b'*!\xa1"^-(\xf3\x105\x05i@B\xc2\xa2\xb7\xdd\xd5\xd5\xa9\xddm\xfae\xa8\\$\xf9d\x1e(',
        ),
        encrypted_data_keys=[
            EncryptedDataKey(
                key_provider=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                encrypted_data_key=b"\xde^\x97\x7f\x84\xe9\x9e\x98\xd0\xe2\xf8\xd5\xcb\xe9\x7f.}\x87\x16,\x11n#\xc8p"
                b"\xdb\xbf\x94\x86*Q\x06\xd2\xf5\xdah\x08\xa4p\x81\xf7\xf4G\x07FzE\xde",
            )
        ],
        encryption_context=_ENCRYPTION_CONTEXT,
        signing_key=_SIGNING_KEY,
        keyring_trace=[
            KeyringTrace(
                wrapping_key=MasterKeyInfo(provider_id=_PROVIDER_ID, key_info=_KEY_ID),
                flags={
                    KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
                    KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY,
                },
            )
        ],
    ),
]

_RAW_RSA_KEYRINGS = [
    RawRSAKeyring(
        key_namespace=_PROVIDER_ID,
        key_name=_KEY_ID,
        wrapping_key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
        wrapping_algorithm=_WRAPPING_ALGORITHM,
    ),
    # RawRSAKeyring.fromPEMEncoding(
    #     key_namespace=_PROVIDER_ID,
    #     key_name=_KEY_ID,
    #     encoded_key=(
    #         b"-----BEGIN RSA PRIVATE KEY-----"
    #         b"MIICXgIBAAKBgQCUjhI8YRPXV8Gfofbg/"
    #         b"PLjWw2AzowQTPErLU2z3+xGqElMdzdiC4Ta43DFWZg34Eg0X8kQPAeoe8h3cRSMo"
    #         b"77eSOHt2dPo7OfTfZqsH8766fivHIKVxBYPX8SZYIUhMtRnlg3uqch9BksfRop+h"
    #         b"f8h/H3lfervJoevS2CXYB9/iwIDAQABAoGBAIqeGzQOHbaGI51yQ2zjez1dPDdiB"
    #         b"F49fZideHEM1GuGIodgguRQ/VJGgncUSC5zcMy2SGaGrVqwznltohAtxy4rZp0eh"
    #         b"2O3aHYi9Wehd0SPLh+qwu7mJDuh0z15hmCOue070FnUtyuSwhXLwDrbot2+5HbmF"
    #         b"9clJLI5tv92gvIpAkEA+Bv5i8XJNPN1rao31aQFoi9bFIOEclk3b1RbLX6mpZBFS"
    #         b"U9CNUy0RQNC0+H3KZ5CTvsyFGpMfTdiFc/Qdesk3QJBAJlHjrvoadP+PU3zXYrWR"
    #         b"D5EryyTxaP1bOjrp9xLuQBeU8x7EVJdpoul9OmwcT3NrAqvxDE9okjha2tjCI6O2"
    #         b"4cCQQDMyOJPYL/zaaPO5LlTKB/SPv4RT4BplYPw6xKa2XeZHhxiJv5B2f7NG6T0G"
    #         b"AWWn16hrCoouZhKngTidfXc7motAkA/KiTgvKr3yHp86AAxWZDv1CAYD6FPqrDB3"
    #         b"3LiLnZDd5uy1ThTJ/Kc87vUnXhdDqeKE9qWrB53SCWbMElzbd17AkEA4DMp+6ngM"
    #         b"o6sS0dY1X6nTLqgvK3B0z5GCAdSEy3Y8jh995Lrl+hy88HzuwUkQwwPlZkFhUNCx"
    #         b"edrC6cTKE5xLA=="
    #         b"-----END RSA PRIVATE KEY-----"
    #     ),
    #     password=None,
    #     wrapping_algorithm=_WRAPPING_ALGORITHM,
    # ),
    # RawRSAKeyring.fromDEREncoding(
    #     key_namespace=_PROVIDER_ID,
    #     key_name=_KEY_ID,
    #     encoded_key=b"-----BEGIN RSA PRIVATE KEY-----\n"
    #                 b"MIIEowIBAAKCAQEAo8uCyhiO4JUGZV+rtNq5DBA9Lm4xkw5kTA3v6EPybs8bVXL2\n"
    #                 b"ZE6jkbo+xT4Jg/bKzUpnp1fE+T1ruGPtsPdoEmhY/P64LDNIs3sRq5U4QV9IETU1\n"
    #                 b"vIcbNNkgGhRjV8J87YNY0tV0H7tuWuZRpqnS+gjV6V9lUMkbvjMCc5IBqQc3heut\n"
    #                 b"/+fH4JwpGlGxOVXI8QAapnSy1XpCr3+PT29kydVJnIMuAoFrurojRpOQbOuVvhtA\n"
    #                 b"gARhst1Ji4nfROGYkj6eZhvkz2Bkud4/+3lGvVU5LO1vD8oY7WoGtpin3h50VcWe\n"
    #                 b"aBT4kejx4s9/G9C4R24lTH09J9HO2UUsuCqZYQIDAQABAoIBAQCfC90bCk+qaWqF\n"
    #                 b"gymC+qOWwCn4bM28gswHQb1D5r6AtKBRD8mKywVvWs7azguFVV3Fi8sspkBA2FBC\n"
    #                 b"At5p6ULoJOTL/TauzLl6djVJTCMM701WUDm2r+ZOIctXJ5bzP4n5Q4I7b0NMEL7u\n"
    #                 b"ixib4elYGr5D1vrVQAKtZHCr8gmkqyx8Mz7wkJepzBP9EeVzETCHsmiQDd5WYlO1\n"
    #                 b"C2IQYgw6MJzgM4entJ0V/GPytkodblGY95ORVK7ZhyNtda+r5BZ6/jeMW+hA3VoK\n"
    #                 b"tHSWjHt06ueVCCieZIATmYzBNt+zEz5UA2l7ksg3eWfVORJQS7a6Ef4VvbJLM9Ca\n"
    #                 b"m1kdsjelAoGBANKgvRf39i3bSuvm5VoyJuqinSb/23IH3Zo7XOZ5G164vh49E9Cq\n"
    #                 b"dOXXVxox74ppj/kbGUoOk+AvaB48zzfzNvac0a7lRHExykPH2kVrI/NwH/1OcT/x\n"
    #                 b"2e2DnFYocXcb4gbdZQ+m6X3zkxOYcONRzPVW1uMrFTWHcJveMUm4PGx7AoGBAMcU\n"
    #                 b"IRvrT6ye5se0s27gHnPweV+3xjsNtXZcK82N7duXyHmNjxrwOAv0SOhUmTkRXArM\n"
    #                 b"6aN5D8vyZBSWma2TgUKwpQYFTI+4Sp7sdkkyojGAEixJ+c5TZJNxZFrUe0FwAoic\n"
    #                 b"c2kb7ntaiEj5G+qHvykJJro5hy6uLnjiMVbAiJDTAoGAKb67241EmHAXGEwp9sdr\n"
    #                 b"2SMjnIAnQSF39UKAthkYqJxa6elXDQtLoeYdGE7/V+J2K3wIdhoPiuY6b4vD0iX9\n"
    #                 b"JcGM+WntN7YTjX2FsC588JmvbWfnoDHR7HYiPR1E58N597xXdFOzgUgORVr4PMWQ\n"
    #                 b"pqtwaZO3X2WZlvrhr+e46hMCgYBfdIdrm6jYXFjL6RkgUNZJQUTxYGzsY+ZemlNm\n"
    #                 b"fGdQo7a8kePMRuKY2MkcnXPaqTg49YgRmjq4z8CtHokRcWjJUWnPOTs8rmEZUshk\n"
    #                 b"0KJ0mbQdCFt/Uv0mtXgpFTkEZ3DPkDTGcV4oR4CRfOCl0/EU/A5VvL/U4i/mRo7h\n"
    #                 b"ye+xgQKBgD58b+9z+PR5LAJm1tZHIwb4tnyczP28PzwknxFd2qylR4ZNgvAUqGtU\n"
    #                 b"xvpUDpzMioz6zUH9YV43YNtt+5Xnzkqj+u9Mr27/H2v9XPwORGfwQ5XPwRJz/2oC\n"
    #                 b"EnPmP1SZoY9lXKUpQXHXSpDZ2rE2Klt3RHMUMHt8Zpy36E8Vwx8o\n"
    #                 b"-----END RSA PRIVATE KEY-----\n",
    #     password=None,
    #     wrapping_algorithm=_WRAPPING_ALGORITHM,
    # )
]


@pytest.mark.parametrize("encryption_materials_samples", _ENCRYPTION_MATERIALS)
@pytest.mark.parametrize("fake_raw_rsa_keyring", _RAW_RSA_KEYRINGS)
def test_raw_rsa_encryption_decryption(encryption_materials_samples, fake_raw_rsa_keyring):

    # Call on_encrypt function for the keyring
    encryption_materials = fake_raw_rsa_keyring.on_encrypt(encryption_materials=encryption_materials_samples)

    # Generate decryption materials
    decryption_materials = DecryptionMaterials(
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, verification_key=b"ex_verification_key"
    )

    # Call on_decrypt function for the keyring
    decryption_materials = fake_raw_rsa_keyring.on_decrypt(
        decryption_materials=decryption_materials, encrypted_data_keys=encryption_materials.encrypted_data_keys
    )

    if decryption_materials.data_encryption_key:
        # Check if the data keys match
        assert encryption_materials.data_encryption_key == decryption_materials.data_encryption_key
