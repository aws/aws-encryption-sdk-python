"""Decrypt Oracle using the AWS Encryption SDK for Python."""
import json
import logging

import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from chalice import Chalice, Response

from .key_providers.counting_master_key import CountingMasterKey
from .key_providers.null_master_key import NullMasterKey

APP = Chalice(app_name="aws-encryption-sdk-decryption-oracle")
APP.log.setLevel(logging.DEBUG)

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Text, NoReturn, Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


def _master_key_provider():
    # type: () -> KMSMasterKeyProvider
    """Build the V0 master key provider."""
    master_key_provider = KMSMasterKeyProvider()
    master_key_provider.add_master_key_provider(NullMasterKey())
    master_key_provider.add_master_key_provider(CountingMasterKey())
    return master_key_provider


@APP.route("/v0/decrypt", methods=["POST"], content_types=["application/octet-stream"])
def basic_decrypt():
    # type: () -> Response
    """Basic decrypt handler for decryption oracle v0.

    The API expects raw ciphertext bytes as the POST body and responds with either:

    1. A 200 response code with the raw plaintext bytes as the body.
    2. A 400 response code with whatever error code was encountered as the body.
    """
    APP.log.debug("Request:")
    APP.log.debug(json.dumps(APP.current_request.to_dict()))
    APP.log.debug("Ciphertext:")
    APP.log.debug(APP.current_request.raw_body)

    try:
        ciphertext = APP.current_request.raw_body
        plaintext, _header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=_master_key_provider())
        APP.log.debug("Plaintext:")
        APP.log.debug(plaintext)
        response = Response(body=plaintext, headers={"Content-Type": "application/octet-stream"}, status_code=200)
    except Exception as error:  # pylint: disable=broad-except
        response = Response(body=str(error), status_code=400)

    APP.log.debug("Response:")
    APP.log.debug(json.dumps(response.to_dict()))
    return response
