# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Basic sanity check for ``aws_encryption_sdk`` client behavior when threading."""
from __future__ import division

import copy
import threading
import time
from random import SystemRandom

import pytest
from six.moves import queue  # six.moves confuses pylint: disable=import-error

import aws_encryption_sdk

from .integration_test_utils import get_cmk_arn, setup_kms_master_key_provider

pytestmark = [pytest.mark.integ]


PLAINTEXT = (
    b'\xa3\xf6\xbc\x89\x95\x15(\xc8}\\\x8d=zu^{JA\xc1\xe9\xf0&m\xe6TD\x03'
    b'\x165F\x85\xae\x96\xd9~ \xa6\x13\x88\xf8\xdb\xc9\x0c\xd8\xd8\xd4\xe0'
    b'\x02\xe9\xdb+\xd4l\xeaq\xf6\xba.cg\xda\xe4V\xd9\x9a\x96\xe8\xf4:\xf5'
    b'\xfd\xd7\xa6\xfa\xd1\x85\xa7o\xf5\x94\xbcE\x14L\xa1\x87\xd9T\xa6\x95'
    b'eZVv\xfe[\xeeJ$a<9\x1f\x97\xe1\xd6\x9dQc\x8b7n\x0f\x1e\xbd\xf5\xba'
    b'\x0e\xae|%\xd8L]\xa2\xa2\x08\x1f'
)


def crypto_thread_worker(crypto_function, start_pause, input_value, output_queue, cache=None):
    """Pauses for ``start_pause`` seconds, then calls ``crypto_function`` with ``input_value`` as source,
    sending output to ``output_queue``.

    :param callable crypto_function: AWS Encryption SDK crypto function to call in each thread
    :param float start_pause: Seconds to pause before running thread (introduces some variability
    to ensure multiple threads run simultaneously)
    :param input_value: Value to pass to ``crypto_function`` as source
    :param output_queue: Queue into which to put output of ``crypto_function`` (ciphertext or decrypted plaintext)
    :param cache: Cache to use with master key provider (optional)
    """
    time.sleep(start_pause)
    kms_master_key_provider = setup_kms_master_key_provider(cache=False)
    if cache is None:
        # For simplicity, always use a caching CMM; just use a null cache if no cache is specified.
        cache = aws_encryption_sdk.NullCryptoMaterialsCache()
    materials_manager = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=kms_master_key_provider,
        cache=cache,
        max_age=60.0
    )
    output_value, _header = crypto_function(
        source=input_value,
        materials_manager=materials_manager
    )
    output_queue.put(output_value)


def get_all_thread_outputs(crypto_function, thread_inputs):
    """Spawn a thread with ``crypto_function`` for each of ``thread_inputs``,
    collecting and returning all outputs.

    :param callable crypto_function: AWS Encryption SDK crypto function to call in each thread
    :param list thread_inputs: List of inputs and pause times to feed to ``crypto_function`` as source.
    :retuns: Outputs (ciphertext or decrypted plaintext) from all threads in no particular order
    :rtype: list
    """
    active_threads = []
    output_queue = queue.Queue()
    for values in thread_inputs:
        _thread = threading.Thread(
            target=crypto_thread_worker,
            kwargs=dict(
                crypto_function=crypto_function,
                output_queue=output_queue,
                **values
            )
        )
        _thread.start()
        active_threads.append(_thread)
    output_values = []
    for _thread in active_threads:
        _thread.join()
        output_values.append(output_queue.get())
    return output_values


def random_pause_time(max_seconds=3):
    """Generates a random pause time between 0.0 and 10.0, limited by max_seconds.

    :param int max_seconds: Maximum pause time (default: 3)
    :rtype: float
    """
    return SystemRandom().random() * 10 % max_seconds


def test_threading_loop():
    """Test thread safety of client."""
    # Check for the CMK ARN first to fail fast if it is not available
    get_cmk_arn()
    rounds = 20
    plaintext_inputs = [
        dict(input_value=copy.copy(PLAINTEXT), start_pause=random_pause_time())
        for _round in range(rounds)
    ]

    ciphertext_values = get_all_thread_outputs(
        crypto_function=aws_encryption_sdk.encrypt,
        thread_inputs=plaintext_inputs
    )
    ciphertext_inputs = [
        dict(input_value=ciphertext, start_pause=random_pause_time())
        for ciphertext in ciphertext_values
    ]

    decrypted_values = get_all_thread_outputs(
        crypto_function=aws_encryption_sdk.decrypt,
        thread_inputs=ciphertext_inputs
    )

    assert all(value == PLAINTEXT for value in decrypted_values)


def test_threading_loop_with_common_cache():
    """Test thread safety of client while using common cryptographic materials cache across all threads."""
    # Check for the CMK ARN first to fail fast if it is not available
    get_cmk_arn()
    rounds = 20
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=40)
    plaintext_inputs = [
        dict(input_value=copy.copy(PLAINTEXT), start_pause=random_pause_time(), cache=cache)
        for _round in range(rounds)
    ]

    ciphertext_values = get_all_thread_outputs(
        crypto_function=aws_encryption_sdk.encrypt,
        thread_inputs=plaintext_inputs
    )
    ciphertext_inputs = [
        dict(input_value=ciphertext, start_pause=random_pause_time(), cache=cache)
        for ciphertext in ciphertext_values
    ]

    decrypted_values = get_all_thread_outputs(
        crypto_function=aws_encryption_sdk.decrypt,
        thread_inputs=ciphertext_inputs
    )

    assert all(value == PLAINTEXT for value in decrypted_values)
