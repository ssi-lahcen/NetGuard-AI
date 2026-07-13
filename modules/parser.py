"""
parser.py

This module is responsible for:

1. Reading the CSV file
2. Validating its structure
3. Cleaning the data
4. Returning a pandas DataFrame
"""

import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "action",
    "bytes"
]


def load_logs(file_path):
    """
    Load network logs from a CSV file.

    Parameters:
        file_path (str): Path to CSV file.

    Returns:
        pandas.DataFrame
    """

    try:
        dataframe = pd.read_csv(file_path)

    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")

    return dataframe

def validate_columns(dataframe):
    """
    Ensure all required columns are present.
    """

    missing = []

    for column in REQUIRED_COLUMNS:

        if column not in dataframe.columns:
            missing.append(column)

    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(missing)}"
        )

    print("Column validation successful.")

def convert_timestamps(dataframe):
    """
    Convert timestamp column to datetime objects.
    """

    dataframe["timestamp"] = pd.to_datetime(
        dataframe["timestamp"],
        errors="coerce"
    )

    return dataframe

def clean_data(dataframe):
    """
    Remove rows with missing values.
    """

    before = len(dataframe)

    dataframe = dataframe.dropna()

    after = len(dataframe)

    print(f"Removed {before - after} invalid rows.")

    return dataframe

def parse_logs(file_path):
    """
    Complete parsing pipeline.
    """

    dataframe = load_logs(file_path)

    validate_columns(dataframe)

    dataframe = convert_timestamps(dataframe)

    dataframe = clean_data(dataframe)

    return dataframe

