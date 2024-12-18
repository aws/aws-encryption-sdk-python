# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script for consolidating results for execution times"""

import argparse
import csv

import numpy as np


def calculate_statistics(_csv_file):
    """Calculate average, trimmed average, minimum, maximum and p99 statistics for execution times in a CSV file."""
    with open(_csv_file, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        data = [float(row[0]) for row in reader]

    output_stats = {}

    # Calculate statistics
    if data:
        data = np.sort(data)
        output_stats['total_entries'] = len(data)
        output_stats['average'] = np.mean(data)
        output_stats['trimmed_average_99_bottom'] = np.mean(data[0:int(0.99 * len(data))])
        output_stats['minimum'] = min(data)
        output_stats['maximum'] = max(data)
        output_stats['perc_99'] = np.percentile(data, 99)
        return output_stats

    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_file',
                        help='csv file containing the outputs of execution times for n_iter iterations')
    args = parser.parse_args()

    statistics = calculate_statistics(args.csv_file)
    if statistics:
        print("CSV File:", args.csv_file)
        print("Total Entries:", statistics['total_entries'])
        print("Average:", statistics['average'])
        print("Bottom 99th percentile trimmed average:", statistics['trimmed_average_99_bottom'])
        print("Minimum:", statistics['minimum'])
        print("Maximum:", statistics['maximum'])
        print("99th percentile:", statistics['perc_99'])
    else:
        print("No data found in the CSV file.")
