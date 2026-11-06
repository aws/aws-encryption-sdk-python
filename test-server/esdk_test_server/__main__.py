# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Entry point: ``python -m esdk_test_server <port>`` starts the Python server.

The port is the first positional argument (mirroring the Java server's
``runServer <port>``), defaulting to the ESDK_TESTSERVER_PORT env var, then 8081.
"""

import os
import sys

from .app import serve


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        port = int(argv[0])
    else:
        port = int(os.environ.get("ESDK_TESTSERVER_PORT", "8081"))
    serve(port)


if __name__ == "__main__":
    main()
