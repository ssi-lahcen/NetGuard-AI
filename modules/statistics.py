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
        "unique_destination_ips": dataframe[
            "dst_ip"
        ].nunique(),
        "unique_ports": dataframe["dst_port"].nunique(),
        "unique_protocols": dataframe[
            "protocol"
        ].nunique(),
        "total_bytes": dataframe["bytes"].sum(),
    }

    return statistics


def get_top_talkers(dataframe, limit=5):
    """
    Identify the most active source IPs.

    Args:
        dataframe (pandas.DataFrame):
            Clean network logs.

        limit (int):
            Number of top IPs to return.

    Returns:
        pandas.Series: Top source IPs.
    """

    top_talkers = (
        dataframe["src_ip"]
        .value_counts()
        .head(limit)
    )

    return top_talkers
def get_top_destination_ports(dataframe, limit=5):
    """
    Identify the most frequently accessed
    destination ports.

    Args:
        dataframe (pandas.DataFrame):
            Clean network logs.

        limit (int):
            Number of top ports to return.

    Returns:
        pandas.Series: Top destination ports.
    """

    top_ports = (
        dataframe["dst_port"]
        .value_counts()
        .head(limit)
    )

    return top_ports

def get_protocol_distribution(dataframe):
    """
    Calculate the distribution of network protocols.

    Args:
        dataframe (pandas.DataFrame):
            Clean network logs.

    Returns:
        pandas.Series: Protocol event counts.
    """

    protocol_distribution = (
        dataframe["protocol"]
        .value_counts()
    )

    return protocol_distribution
def build_network_profile(dataframe):
    """
    Build a complete network behavior profile.

    Args:
        dataframe (pandas.DataFrame):
            Clean network logs.

    Returns:
        dict: Complete network profile.
    """

    network_profile = {
        "basic_statistics": (
            calculate_basic_statistics(dataframe)
        ),
        "top_talkers": (
            get_top_talkers(dataframe)
        ),
        "top_ports": (
            get_top_destination_ports(dataframe)
        ),
        "protocol_distribution": (
            get_protocol_distribution(dataframe)
        ),
    }

    return network_profile
