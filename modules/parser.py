"""
==================================================
NetGuard-AI
Parser Module
==================================================

Reads and validates network log files.

Author:
    Lahcen Elkadi
"""

from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes"
]


def validate_columns(dataframe: pd.DataFrame) -> None:
    """
    Verify that all required columns exist.

    Raises:
        ValueError
    """

    missing_columns = []

    for column in REQUIRED_COLUMNS:

        if column not in dataframe.columns:

            missing_columns.append(column)

    if missing_columns:

        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )


def convert_data_types(
    dataframe: pd.DataFrame
) -> pd.DataFrame:
    """
    Convert columns into appropriate data types.
    """

    dataframe["timestamp"] = pd.to_datetime(
        dataframe["timestamp"],
        errors="coerce"
    )

    dataframe["dst_port"] = pd.to_numeric(
        dataframe["dst_port"],
        errors="coerce"
    )

    dataframe["bytes"] = pd.to_numeric(
        dataframe["bytes"],
        errors="coerce"
    )

    return dataframe


def remove_invalid_rows(
    dataframe: pd.DataFrame
) -> pd.DataFrame:
    """
    Remove rows containing invalid values.
    """

    before = len(dataframe)

    dataframe = dataframe.dropna()

    removed = before - len(dataframe)

    print(
        f"Removed {removed} invalid rows."
    )

    return dataframe


def parse_logs(
    log_file: str
) -> pd.DataFrame:
    """
    Read and validate a CSV log file.
    """

    log_path = Path(log_file)

    if not log_path.exists():

        raise FileNotFoundError(
            f"File not found: {log_file}"
        )

    dataframe = pd.read_csv(log_path)

    validate_columns(dataframe)

    print("Column validation successful.")

    dataframe = convert_data_types(
        dataframe
    )

    dataframe = remove_invalid_rows(
        dataframe
    )

    return dataframe
