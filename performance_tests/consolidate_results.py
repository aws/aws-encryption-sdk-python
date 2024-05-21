# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script for consolidating results for execution times"""

import csv
import argparse
import numpy as np


def calculate_statistics(_csv_file):
    """Calculate min, max, average and p99 statistics for execution times in a CSV file."""
    with open(_csv_file, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        data = [float(row[0]) for row in reader]

    # Calculate statistics
    if data:
        _total_entries = len(data)
        _average = sum(data) / _total_entries
        _minimum = min(data)
        _maximum = max(data)
        _perc_99 = np.percentile(data, 99) 
        return _total_entries, _average, _minimum, _maximum, _perc_99

    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_file',
                        help='csv file containing the outputs of execution times for n_iter iterations')
    args = parser.parse_args()

    statistics = calculate_statistics(args.csv_file)
    if statistics:
        total_entries, average, minimum, maximum, perc_99 = statistics
        print("CSV File:", args.csv_file)
        print("Total Entries:", total_entries)
        print("Average:", average)
        print("Minimum:", minimum)
        print("Maximum:", maximum)
        print("99th percentile:", perc_99)
    else:
        print("No data found in the CSV file.")
