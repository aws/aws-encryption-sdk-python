"""

"""
import base64
import json
import logging

import aws_encryption_sdk
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from chalice import Chalice

from .key_providers.counting_master_key import CountingMasterKey
from .key_providers.null_master_key import NullMasterKey

APP = Chalice(app_name="aws-encryption-sdk-decryption-oracle")
_LOGGER = logging.getLogger("aws-encryption-sdk-decryption-oracle")

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
    # type: () -> Dict[Text, Union[Text, bool, int]]
    """Basic decrypt handler for decryption oracle v0."""
    _LOGGER.debug("Request:")
    _LOGGER.debug(json.dumps(APP.current_request.to_dict()))

    try:
        request = APP.current_request.json_body
        ciphertext = base64.b64decode(request["body"].encode("utf-8"))
        plaintext, _header = aws_encryption_sdk.decrypt(source=ciphertext, key_provider=_master_key_provider())
        response = {"body": base64.b64encode(plaintext), "isBase64Encoded": True, "statusCode": 200}
    except Exception as error:  # pylint: disable=broad-except
        response = {"body": str(error), "isBase64Encoded": False, "statusCode": 400}

    _LOGGER.debug("Response:")
    _LOGGER.debug(json.dumps(response))
    return response
