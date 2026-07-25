"""
==================================================
NetGuard-AI
Parser Module
==================================================

Reads, validates, and cleans log files.

Supported Schemas:
    - network
    - auth

Author:
    Lahcen Elkadi
"""

from pathlib import Path

import pandas as pd


# ==================================================
# Supported Schemas
# ==================================================

SCHEMAS = {

    "network": [
        "timestamp",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "bytes"
    ],

    "auth": [
        "timestamp",
        "src_ip",
        "dst_ip",
        "service",
        "status",
        "username"
    ]
}


# ==================================================
# Validate Columns
# ==================================================

def validate_columns(
    dataframe: pd.DataFrame,
    schema: str
) -> None:
    """
    Verify that all required columns exist.
    """

    if schema not in SCHEMAS:

        raise ValueError(
            f"Unknown schema: {schema}"
        )

    required_columns = SCHEMAS[schema]

    missing_columns = []

    for column in required_columns:

        if column not in dataframe.columns:

            missing_columns.append(column)

    if missing_columns:

        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    print("Column validation successful.")


# ==================================================
# Convert Data Types
# ==================================================

def convert_data_types(
    dataframe: pd.DataFrame,
    schema: str
) -> pd.DataFrame:
    """
    Convert columns into appropriate data types.
    """

    dataframe["timestamp"] = pd.to_datetime(
        dataframe["timestamp"],
        errors="coerce"
    )

    if schema == "network":

        dataframe["dst_port"] = pd.to_numeric(
            dataframe["dst_port"],
            errors="coerce"
        )

        dataframe["bytes"] = pd.to_numeric(
            dataframe["bytes"],
            errors="coerce"
        )

    return dataframe


# ==================================================
# Remove Invalid Rows
# ==================================================

def remove_invalid_rows(
    dataframe: pd.DataFrame,
    schema: str
) -> pd.DataFrame:
    """
    Remove rows containing invalid values.
    """

    before = len(dataframe)

    if schema == "network":

        dataframe = dataframe.dropna(
            subset=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "dst_port",
                "protocol",
                "bytes"
            ]
        )

    elif schema == "auth":

        dataframe = dataframe.dropna(
            subset=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "service",
                "status",
                "username"
            ]
        )

    removed = before - len(dataframe)

    print(
        f"Removed {removed} invalid rows."
    )

    return dataframe


# ==================================================
# Parse Logs
# ==================================================

def parse_logs(
    log_file: str,
    schema: str = "network"
) -> pd.DataFrame:
    """
    Read, validate, clean, and return a log file.

    Parameters
    ----------
    log_file : str
        Path to the CSV file.

    schema : str
        Log schema ("network" or "auth").

    Returns
    -------
    pandas.DataFrame
        Cleaned dataframe.
    """

    log_path = Path(log_file)

    if not log_path.exists():

        raise FileNotFoundError(
            f"File not found: {log_file}"
        )

    dataframe = pd.read_csv(log_path)

    validate_columns(
        dataframe,
        schema
    )

    dataframe = convert_data_types(
        dataframe,
        schema
    )

    dataframe = remove_invalid_rows(
        dataframe,
        schema
    )

    return dataframe
