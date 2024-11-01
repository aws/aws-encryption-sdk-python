#####################################
aws-encryption-sdk performance tests
#####################################

This module runs performance tests for the `AWS Encryption SDK Python`_.

********
Overview
********

This module tests the following keyrings / master key providers:

1. KMS Keyring / KMS Master Key Provider
2. Raw AES Keyring / AES Master Key Provider
3. Raw RSA Keyring / RSA Master Key Provider
4. Hierarchy Keyring
5. Caching CMM

For each test on the above keyrings / master key providers, this package measures:

1. Execution time
2. Total memory consumption

For each keyring / master key provider, the execution time and memory consumption
is measured for three operations:

1. Create keyring / master key provider
2. Encrypt
3. Decrypt

The usage of the performance tests is demonstrated through an `AWS KMS Keyring`_.
However, the procedure is the same for any keyring / master key provider, with slight
changes in the input arguments.

The results for the performance test will be available in the results folder in the
performance_tests directory.

**********************
Required Prerequisites
**********************

* Python 3.8+
* aws-encryption-sdk
* boto3 >= 1.10.0
* click
* tqdm
* pytest

Recommended Prerequisites
=========================

* aws-cryptographic-material-providers: == 1.7.3
  * Requires Python 3.11+.

*****
Usage
*****

Execution Time
==============

Create Keyring
--------------
To run the performance test for execution time, please use the
following commands in the performance_tests directory.

.. code::

    usage: python test/keyrings/test_aws_kms_keyring.py create

    Create a keyring to use for encryption and decryption.

    optional arguments:
      -h, --help                    show this help message and exit.
      --kms_key_id KMS_KEY_ID       The KMS key ID you want to use.
      --n_iters N_ITERS             Number of iterations you want to
                                    run the test for. For instance,
                                    if n_iters = 100, this performance
                                    test script will run the create_keyring
                                    method 100 times and report the
                                    execution time of each of the calls.
      --output_file OUTPUT_FILE     The output file for execution times
                                    for each function call,
                                    default='kms_keyring_create' in the
                                    results folder.

Encrypt
-------

To run the performance test for execution time, please use the following
commands in the performance_tests directory:

.. code::

    usage: python test/keyrings/test_aws_kms_keyring.py encrypt

    optional arguments:
      -h, --help                                            show this help message and exit.
      --plaintext_data_filename PLAINTEXT_DATA_FILENAME     Filename containing plaintext data
                                                            you want to encrypt.
                                                            default='test/resources/plaintext/plaintext-data-medium.dat'.
                                                            You can choose to use any other plaintext
                                                            file as well. Some example plaintext
                                                            data files are present in the
                                                            'test/resources' directory.
      --kms_key_id KMS_KEY_ID                               The KMS key ID you want to use.
      --n_iters N_ITERS                                     Number of iterations you want to
                                                            run the test for. For instance,
                                                            if n_iters = 100, this performance
                                                            test script will run the create_keyring
                                                            method 100 times and report the
                                                            execution time of each of the calls.
      --output_file OUTPUT_FILE                             The output file for execution times
                                                            for each function call,
                                                            default='kms_keyring_create' in the
                                                            results folder.

Decrypt
-------

To run the performance test for execution time, please use the
following commands in the performance_tests directory

.. code::

    usage: python test/keyrings/test_aws_kms_keyring.py decrypt

    optional arguments:
      -h, --help                                            show this help message and exit.
      --ciphertext_data_filename CIPHERTEXT_DATA_FILENAME   Filename containing ciphertext data
                                                            you want to decrypt.
                                                            default='test/resources/ciphertext/kms/ciphertext-data-medium.ct'.
                                                            You can choose to use any other
                                                            ciphertext file as well. Some example
                                                            ciphertext data files are present in
                                                            the 'test/resources' directory.
      --kms_key_id KMS_KEY_ID                               The KMS key ID you want to use.
      --n_iters N_ITERS                                     Number of iterations you want to
                                                            run the test for. For instance,
                                                            if n_iters = 100, this performance
                                                            test script will run the create_keyring
                                                            method 100 times and report the
                                                            execution time of each of the calls.
      --output_file OUTPUT_FILE                             The output file for execution times
                                                            for each function call,
                                                            default='kms_keyring_create' in the
                                                            results folder.

Consolidate Time Results
========================

In order to find the minimum, maximum, average, 99th percentile and bottom
99th percentile trimmed average times from the n_iters runs, please use the
following script from the performance_tests directory with the csv file
containing times for each of the n_iters runs generated in the previous
"Execution Time" section:

.. code::

    usage: python consolidate_results.py results/kms_keyring_decrypt.csv

Memory Consumption
==================

To get the memory consumption, simply replace 'python'
with 'mprof run' in the previously mentioned commands.

For example, if you want to calculate the memory consumption
of the encrypt function of a AWS KMS Keyring, simply write:

.. code::

    usage: mprof run test/keyrings/test_aws_kms_keyring.py encrypt


This should generate an mprofile log file in your current directory.
This mprofile log file contains the total memory consumed by the program
with respect to time elapsed.
To plot the memory consumption with respect to time, please use the following
command from the same directory

.. code::

    usage: mprof plot


This 'mprof plot' command will plot the most recent mprofile log file.


Performance Graph
=================

To generate a performance graph, please use the following command
to generate the pstats log file by specifying the output pstats file
path. Here, 'results/kms_keyring_create.pstats' is set as the default
output file.

.. code::

    usage: python -m cProfile -o results/kms_keyring_create.pstats test/keyrings/test_aws_kms_keyring.py create


After generating the pstats file, please run the following command
to generate the performance graph. The output performance graph will
be a .png file that you specify. Here, 'results/kms_keyring_create.png'
is set as the default output file.

.. code::

    usage: gprof2dot -f pstats results/kms_keyring_create.pstats | dot -Tpng -o results/kms_keyring_create.png && eog results/kms_keyring_create.png


Note: This project does not adhere to semantic versioning; as such it
makes no guarantees that functionality will persist across major,
minor, or patch versions.
**DO NOT** take a standalone dependency on this library.

.. _AWS Encryption SDK Python: https://github.com/aws/aws-encryption-sdk-python/
.. _AWS KMS Keyring: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html
