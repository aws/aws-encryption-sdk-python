# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Script for consolidating results for execution times"""

import csv
import sys


def calculate_statistics(_csv_file):
    """Calculate min, max and average statistics for execution times in a CSV file."""
    with open(_csv_file, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        data = [float(row[0]) for row in reader]

    # Calculate statistics
    if data:
        _total_entries = len(data)
        _average = sum(data) / _total_entries
        _minimum = min(data)
        _maximum = max(data)
        return _total_entries, _average, _minimum, _maximum

    return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python consolidate_results.py <csv_file>")
        sys.exit(1)

    csv_file = sys.argv[1]
    statistics = calculate_statistics(csv_file)
    if statistics:
        total_entries, average, minimum, maximum = statistics
        print("CSV File:", csv_file)
        print("Total Entries:", total_entries)
        print("Average:", average)
        print("Minimum:", minimum)
        print("Maximum:", maximum)
    else:
        print("No data found in the CSV file.")
