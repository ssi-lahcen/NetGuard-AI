"""
parser.py

Responsible for loading, validating,
cleaning, and preparing network logs.
"""

import ipaddress

import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "action",
    "bytes",
]


def load_logs(file_path):
    """
    Load network logs from a CSV file.

    Args:
        file_path (str): Path to the CSV file.

    Returns:
        pandas.DataFrame: Loaded logs.
    """

    try:
        dataframe = pd.read_csv(file_path)

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    return dataframe


def validate_columns(dataframe):
    """
    Validate the required columns.
    """

    missing_columns = []

    for column in REQUIRED_COLUMNS:

        if column not in dataframe.columns:
            missing_columns.append(column)

    if missing_columns:
        raise ValueError(
            "Missing required columns: "
            f"{', '.join(missing_columns)}"
        )

    print("Column validation successful.")


def convert_timestamps(dataframe):
    """
    Convert timestamps into datetime objects.
    """

    dataframe["timestamp"] = pd.to_datetime(
        dataframe["timestamp"],
        errors="coerce",
    )

    return dataframe


def validate_ip(ip_address):
    """
    Validate an IPv4 or IPv6 address.

    Returns:
        bool: True if valid, False otherwise.
    """

    try:
        ipaddress.ip_address(ip_address)
        return True

    except ValueError:
        return False


def validate_network_data(dataframe):
    """
    Validate IP addresses and network values.
    """

    invalid_source_ips = ~dataframe["src_ip"].apply(
        validate_ip
    )

    invalid_destination_ips = ~dataframe["dst_ip"].apply(
        validate_ip
    )

    invalid_ports = (
        (dataframe["dst_port"] < 1)
        | (dataframe["dst_port"] > 65535)
    )

    invalid_bytes = dataframe["bytes"] < 0

    invalid_rows = (
        invalid_source_ips
        | invalid_destination_ips
        | invalid_ports
        | invalid_bytes
    )

    invalid_count = invalid_rows.sum()

    if invalid_count > 0:

        print(
            f"Warning: {invalid_count} invalid "
            "network rows detected."
        )

    return dataframe[~invalid_rows]


def clean_data(dataframe):
    """
    Remove missing and duplicate rows.
    """

    before = len(dataframe)

    dataframe = dataframe.dropna()

    dataframe = dataframe.drop_duplicates()

    dataframe = dataframe.dropna(
        subset=["timestamp"]
    )

    after = len(dataframe)

    removed_rows = before - after

    print(
        f"Removed {removed_rows} invalid rows."
    )

    return dataframe


def parse_logs(file_path):
    """
    Execute the complete log processing pipeline.
    """

    dataframe = load_logs(file_path)

    validate_columns(dataframe)

    dataframe = convert_timestamps(dataframe)

    dataframe = validate_network_data(dataframe)

    dataframe = clean_data(dataframe)

    return dataframe
