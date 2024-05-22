# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for AWS Encryption SDK performance tests."""


class PerfTestUtils:
    """Utility functions for AWS Encryption SDK performance tests."""
    DEFAULT_N_ITERS = 100
    DEFAULT_FILE_SIZE = 'small'

    @staticmethod
    def read_file(filename):
        """Returns the contents of the file."""
        with open(filename, 'rb') as file:
            return file.read()

    @staticmethod
    def get_rsa_key_from_file(filename):
        """Returns the RSA key"""
        with open(filename, "r", encoding='utf-8') as f:
            key = f.read()

        # Convert the key from a string to bytes
        key = bytes(key, 'utf-8')

        return key

    @staticmethod
    def print_time_list_to_csv(time_list, filename):
        """Prints the time list to a CSV file."""
        with open('results/' + filename + '.csv', 'w', encoding='utf-8') as myfile:
            for time in time_list:
                myfile.write(str(time) + '\n')
