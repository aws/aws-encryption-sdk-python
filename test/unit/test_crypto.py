# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for aws_encryption_sdk.internal.crypto"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

VALUES = {
    "iv": b"asdfzxcvqwer",
    "tag": b"asdfzxcvqwerasdf",
    "random": b"dihfoah\x23\x66",
    "encryptor": {"update": b"ex_update_ciphertext", "finalize": b"ex_finalize_ciphertext"},
    "decryptor": {"update": b"ex_update_plaintext", "finalize": b"ex_finalize_plaintext"},
    "ecc_private_key_prime": ec.EllipticCurvePrivateNumbers(
        private_value=17889917494901019016174171250566479258605401433636341402964733440624721474929058596523395852088194487740674876114796,  # noqa pylint: disable=line-too-long
        public_numbers=ec.EllipticCurvePublicNumbers(
            x=9007459108199787568878509110290896090564999412935334592925575746287962476803074379865243742719141579140901207554948,  # noqa pylint: disable=line-too-long
            y=1574487057865803742065434835341798147751257167933485863820054382900062216413864643113244902766112081885540347590369,  # noqa pylint: disable=line-too-long
            curve=ec.SECP384R1(),
        ),
    ).private_key(default_backend()),
    "ecc_compressed_point": (
        b"\x03:\x85\xcb\xea\x11\x13\x03\x9d\x90\xf4HU\x7f\xbbj\xa1\xe1\n\xfa"
        b"\x95\xd2\xe5\xa1\xaf|\x94\x98iD\x07\xd4{S\xd1\xa4o\xfa\xcdY\x03\x11"
        b"\x91\x12E^\xd4;\x84"
    ),
    "ecc_private_key_prime_private_bytes": (
        b'0\x81\xb6\x02\x01\x000\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x04\x81\x9e0\x81\x9b\x02\x01\x01'
        b"\x040t;\xaf\x05\xff\xd2LF%6a\xf7V8\xa3\xa5})\xd6\x19\x16{)\xa2\x98\xeb3\x97\xebOS?\x18\xfa+\xf0\xa1V\xe2\x81"
        b"\xa8\xaa\x9b\x871H\x07l\xa1d\x03b\x00\x04:\x85\xcb\xea\x11\x13\x03\x9d\x90\xf4HU\x7f\xbbj\xa1\xe1\n\xfa\x95"
        b"\xd2\xe5\xa1\xaf|\x94\x98iD\x07\xd4{S\xd1\xa4o\xfa\xcdY\x03\x11\x91\x12E^\xd4;\x84\n:\xcaD\x1f)\xde\xf73\x9a!"
        b"/x#(z\xf8/\x83\xeb\r&\x7f&\xb4\xeb\xc1\x1b\xe9\x91I\xf5\x8a\xb6\xee\xaf\x08\xb9\xa5\xe1S\xb2Gw\x15(\xb6\xe1"
    ),
    "ecc_private_key_prime_public_bytes": (
        b'0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03b\x00\x04:\x85\xcb\xea\x11\x13\x03\x9d\x90\xf4HU'
        b"\x7f\xbbj\xa1\xe1\n\xfa\x95\xd2\xe5\xa1\xaf|\x94\x98iD\x07\xd4{S\xd1\xa4o\xfa\xcdY\x03\x11\x91\x12E^\xd4;\x84"
        b"\n:\xcaD\x1f)\xde\xf73\x9a!/x#(z\xf8/\x83\xeb\r&\x7f&\xb4\xeb\xc1\x1b\xe9\x91I\xf5\x8a\xb6\xee\xaf\x08\xb9"
        b"\xa5\xe1S\xb2Gw\x15(\xb6\xe1"
    ),
    "ecc_private_key_char2": ec.EllipticCurvePrivateNumbers(
        private_value=131512833187976200862897177240257889476359607892474090119002870596121284569326171944650239612201181144875264734209664973820,  # noqa pylint: disable=line-too-long
        public_numbers=ec.EllipticCurvePublicNumbers(
            x=783372629152728216190118671643020486604880277607267246139026062120084499867233383227220456289236528291350315438332972681898,  # noqa pylint: disable=line-too-long
            y=657053766035459398820670308946963262342583342616783849689721971058264156234178067988487273332138651529574836305189297847674,  # noqa pylint: disable=line-too-long
            curve=ec.SECT409K1(),
        ),
    ).private_key(default_backend()),
}
VALUES["ciphertext"] = VALUES["encryptor"]["update"] + VALUES["encryptor"]["finalize"]
VALUES["plaintext"] = VALUES["decryptor"]["update"] + VALUES["decryptor"]["finalize"]
