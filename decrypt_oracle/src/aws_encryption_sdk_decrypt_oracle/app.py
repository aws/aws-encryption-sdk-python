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
"""Decrypt Oracle powered by the AWS Encryption SDK for Python."""
import json
import logging
import os

import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import DiscoveryAwsKmsMasterKeyProvider
from chalice import Chalice, Response

from .key_providers.counting import CountingMasterKey
from .key_providers.null import NullMasterKey

CHALICE_DEBUG = os.environ.get("CHALICE_DEBUG", "no") == "yes"
APP = Chalice(app_name="aws-encryption-sdk-decrypt-oracle", debug=CHALICE_DEBUG)
APP.log.setLevel(logging.DEBUG)


def _master_key_provider() -> DiscoveryAwsKmsMasterKeyProvider:
    """Build the V0 master key provider."""
    master_key_provider = DiscoveryAwsKmsMasterKeyProvider()
    master_key_provider.add_master_key_provider(NullMasterKey())
    master_key_provider.add_master_key_provider(CountingMasterKey())
    return master_key_provider


@APP.route("/v0/decrypt", methods=["POST"], content_types=["application/octet-stream"])
def basic_decrypt() -> Response:
    """Basic decrypt handler for decrypt oracle v0.

    **Request**

    * **Method**: POST
    * **Body**: Raw ciphertext bytes
    * **Headers**:

      * **Content-Type**: ``application/octet-stream``
      * **Accept**: ``application/octet-stream``

    **Response**

    * 200 response code with the raw plaintext bytes as the body
    * 400 response code with whatever error code was encountered as the body
    """
    APP.log.debug("Request:")
    APP.log.debug(json.dumps(APP.current_request.to_dict()))
    APP.log.debug("Ciphertext:")
    APP.log.debug(APP.current_request.raw_body)

    try:
        client = aws_encryption_sdk.EncryptionSDKClient()
        ciphertext = APP.current_request.raw_body
        plaintext, _header = client.decrypt(source=ciphertext, key_provider=_master_key_provider())
        APP.log.debug("Plaintext:")
        APP.log.debug(plaintext)
        response = Response(body=plaintext, headers={"Content-Type": "application/octet-stream"}, status_code=200)
    except Exception as error:  # pylint: disable=broad-except
        response = Response(body=str(error), status_code=400)

    APP.log.debug("Response:")
    APP.log.debug(json.dumps(response.to_dict(binary_types=["application/octet-stream"])))
    return response
