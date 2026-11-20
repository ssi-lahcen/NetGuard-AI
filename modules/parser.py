"""
Responsible for loading, validating, cleaning, and preparing network logs.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import pandas as pd


REQUIRED_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "action",
    "bytes",
)


class LogValidationError(ValueError):
    """Raised when a log file cannot be processed safely."""


def load_logs(file_path: str | Path) -> pd.DataFrame:
    """Load a CSV log file and return a DataFrame."""

    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError as exc:
        raise LogValidationError(f"Log file is empty: {path}") from exc
    except (pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise LogValidationError(f"Unable to parse CSV file: {path}") from exc
    except OSError as exc:
        raise LogValidationError(f"Unable to read log file: {path}: {exc}") from exc


def validate_columns(dataframe: pd.DataFrame) -> None:
    """Validate that all required columns are present."""

    missing_columns = [column for column in REQUIRED_COLUMNS if column not in dataframe.columns]
    if missing_columns:
        raise LogValidationError("Missing required columns: " + ", ".join(missing_columns))


def convert_timestamps(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Convert timestamps to timezone-naive UTC datetime values."""

    result = dataframe.copy()
    timestamps = pd.to_datetime(result["timestamp"], errors="coerce", utc=True)
    result["timestamp"] = timestamps.dt.tz_convert(None)
    return result


def validate_ip(ip_address_value: Any) -> bool:
    """Return True when a value is a valid IPv4 or IPv6 address."""

    if ip_address_value is None or pd.isna(ip_address_value):
        return False
    try:
        ipaddress.ip_address(str(ip_address_value).strip())
        return True
    except (TypeError, ValueError):
        return False


def _normalize_text(dataframe: pd.DataFrame) -> pd.DataFrame:
    result = dataframe.copy()
    for column in ("src_ip", "dst_ip", "protocol", "action"):
        result[column] = result[column].where(result[column].notna(), "")
        result[column] = result[column].astype("string").str.strip()
    result["protocol"] = result["protocol"].str.upper()
    result["action"] = result["action"].str.upper()
    return result


def validate_network_data(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Validate IP addresses, ports, and byte counts."""

    result = _normalize_text(dataframe)
    result["dst_port"] = pd.to_numeric(result["dst_port"], errors="coerce")
    result["bytes"] = pd.to_numeric(result["bytes"], errors="coerce")

    invalid_source_ips = ~result["src_ip"].apply(validate_ip)
    invalid_destination_ips = ~result["dst_ip"].apply(validate_ip)
    invalid_ports = result["dst_port"].isna() | ~result["dst_port"].between(1, 65535)
    invalid_bytes = result["bytes"].isna() | (result["bytes"] < 0)

    invalid_rows = invalid_source_ips | invalid_destination_ips | invalid_ports | invalid_bytes
    valid = result.loc[~invalid_rows].copy()
    valid["dst_port"] = valid["dst_port"].astype("int64")
    valid["bytes"] = valid["bytes"].astype("int64")
    return valid


def clean_data(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Remove missing values, invalid timestamps, and duplicate rows."""

    result = dataframe.dropna(subset=list(REQUIRED_COLUMNS)).drop_duplicates()
    result = result[result["timestamp"].notna()].copy()
    return result.reset_index(drop=True)


def parse_logs_with_report(file_path: str | Path) -> tuple[pd.DataFrame, dict[str, int]]:
    """Execute the complete pipeline and return data plus removal counts."""

    dataframe = load_logs(file_path)
    validate_columns(dataframe)

    original_count = len(dataframe)
    dataframe = convert_timestamps(dataframe)
    dataframe = validate_network_data(dataframe)
    dataframe = clean_data(dataframe)

    report = {
        "loaded_rows": original_count,
        "valid_rows": len(dataframe),
        "removed_rows": original_count - len(dataframe),
    }
    return dataframe, report


def parse_logs(file_path: str | Path) -> pd.DataFrame:
    """Backward-compatible entry point for log parsing."""

    dataframe, _ = parse_logs_with_report(file_path)
    return dataframe
