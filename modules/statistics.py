"""
statistics.py

Responsible for analyzing
network log statistics.
"""

import pandas as pd


def calculate_basic_statistics(dataframe):
    """
    Calculate basic network statistics.

    Args:
        dataframe (pandas.DataFrame):
            Clean network logs.

    Returns:
        dict: Basic network statistics.
    """

    statistics = {
        "total_events": len(dataframe),
        "unique_source_ips": dataframe["src_ip"].nunique(),
        "unique_destination_ips": dataframe["dst_ip"].nunique(),
        "unique_ports": dataframe["dst_port"].nunique(),
        "unique_protocols": dataframe["protocol"].nunique(),
        "total_bytes": dataframe["bytes"].sum(),
    }

    return statistics
