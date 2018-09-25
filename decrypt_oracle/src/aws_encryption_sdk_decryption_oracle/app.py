"""

"""
import base64
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
    """Basic decrypt handler for decryption oracle v0."""
    APP.log.debug("Request:")
    APP.log.debug(json.dumps(APP.current_request.to_dict()))

    try:
        request = APP.current_request.json_body
        ciphertext = base64.b64decode(request["body"].encode("utf-8"))
        plaintext, _header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=_master_key_provider())
        response = Response(
            body=plaintext,
            headers={'Content-Type': 'application/octet-stream'},
            status_code=200
        )
        # response = {"body": base64.b64encode(plaintext), "isBase64Encoded": True, "statusCode": 200}
    except Exception as error:  # pylint: disable=broad-except
        response = Response(
            body=str(error),
            status_code=400
        )
        # response = {"body": str(error), "isBase64Encoded": False, "statusCode": 400}

    APP.log.debug("Response:")
    APP.log.debug(str(response))
    return response
