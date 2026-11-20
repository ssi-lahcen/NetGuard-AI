"""Network statistics and behavior profile helpers."""

from __future__ import annotations

import pandas as pd


def _require_limit(limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")


def calculate_basic_statistics(dataframe: pd.DataFrame) -> dict[str, int]:
    """Calculate basic network statistics."""

    if dataframe.empty:
        return {
            "total_events": 0,
            "unique_source_ips": 0,
            "unique_destination_ips": 0,
            "unique_ports": 0,
            "unique_protocols": 0,
            "total_bytes": 0,
        }

    return {
        "total_events": int(len(dataframe)),
        "unique_source_ips": int(dataframe["src_ip"].nunique()),
        "unique_destination_ips": int(dataframe["dst_ip"].nunique()),
        "unique_ports": int(dataframe["dst_port"].nunique()),
        "unique_protocols": int(dataframe["protocol"].nunique()),
        "total_bytes": int(dataframe["bytes"].sum()),
    }


def get_top_talkers(dataframe: pd.DataFrame, limit: int = 5) -> pd.Series:
    """Identify the most active source IP addresses."""

    _require_limit(limit)
    if dataframe.empty:
        return pd.Series(dtype="int64")
    return dataframe["src_ip"].value_counts().head(limit)


def get_top_destination_ports(dataframe: pd.DataFrame, limit: int = 5) -> pd.Series:
    """Identify the most frequently used destination ports."""

    _require_limit(limit)
    if dataframe.empty:
        return pd.Series(dtype="int64")
    return dataframe["dst_port"].value_counts().head(limit)


def get_protocol_distribution(dataframe: pd.DataFrame) -> pd.Series:
    """Calculate protocol event counts."""

    if dataframe.empty:
        return pd.Series(dtype="int64")
    return dataframe["protocol"].value_counts()


def get_action_distribution(dataframe: pd.DataFrame) -> pd.Series:
    """Calculate allowed and denied action event counts."""

    if dataframe.empty:
        return pd.Series(dtype="int64")
    return dataframe["action"].value_counts()


def build_network_profile(dataframe: pd.DataFrame, limit: int = 5) -> dict:
    """Build a complete network behavior profile."""

    _require_limit(limit)
    return {
        "basic_statistics": calculate_basic_statistics(dataframe),
        "top_talkers": get_top_talkers(dataframe, limit),
        "top_ports": get_top_destination_ports(dataframe, limit),
        "protocol_distribution": get_protocol_distribution(dataframe),
        "action_distribution": get_action_distribution(dataframe),
    }
