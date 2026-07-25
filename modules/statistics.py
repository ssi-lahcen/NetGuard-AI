"""
==================================================
NetGuard-AI
Statistics Module
==================================================

Builds network statistics used by the detection engine.

Author:
    Lahcen Elkadi
"""

from typing import Any

import pandas as pd


# ==================================================
# Basic Statistics
# ==================================================

def get_basic_statistics(
    dataframe: pd.DataFrame
) -> dict[str, Any]:
    """
    Compute basic network statistics.
    """

    return {

        "total_events": len(dataframe),

        "unique_source_ips":
            dataframe["src_ip"].nunique(),

        "unique_destination_ips":
            dataframe["dst_ip"].nunique(),

        "unique_ports":
            dataframe["dst_port"].nunique(),

        "unique_protocols":
            dataframe["protocol"].nunique(),

        "total_bytes":
            int(dataframe["bytes"].sum())

    }


# ==================================================
# Top Talkers
# ==================================================

def get_top_talkers(
    dataframe: pd.DataFrame,
    top_n: int = 10
) -> dict:
    """
    Return the hosts generating the most traffic.
    """

    return (

        dataframe["src_ip"]

        .value_counts()

        .head(top_n)

        .to_dict()

    )


# ==================================================
# Top Destination Ports
# ==================================================

def get_top_ports(
    dataframe: pd.DataFrame,
    top_n: int = 10
) -> dict:
    """
    Return the most contacted destination ports.
    """

    return (

        dataframe["dst_port"]

        .value_counts()

        .head(top_n)

        .to_dict()

    )


# ==================================================
# Protocol Distribution
# ==================================================

def get_protocol_distribution(
    dataframe: pd.DataFrame
) -> dict:
    """
    Count events by protocol.
    """

    return (

        dataframe["protocol"]

        .value_counts()

        .to_dict()

    )


# ==================================================
# Top Destination IPs
# ==================================================

def get_top_destinations(
    dataframe: pd.DataFrame,
    top_n: int = 10
) -> dict:
    """
    Return the most contacted destination IPs.
    """

    return (

        dataframe["dst_ip"]

        .value_counts()

        .head(top_n)

        .to_dict()

    )


# ==================================================
# Traffic Volume by Protocol
# ==================================================

def get_bytes_per_protocol(
    dataframe: pd.DataFrame
) -> dict:
    """
    Calculate total transferred bytes per protocol.
    """

    return (

        dataframe

        .groupby("protocol")["bytes"]

        .sum()

        .to_dict()

    )


# ==================================================
# Build Network Profile
# ==================================================

def build_network_profile(
    dataframe: pd.DataFrame
) -> dict:
    """
    Build the complete network profile.
    """

    return {

        "basic_statistics":
            get_basic_statistics(dataframe),

        "top_talkers":
            get_top_talkers(dataframe),

        "top_ports":
            get_top_ports(dataframe),

        "protocol_distribution":
            get_protocol_distribution(dataframe),

        "top_destinations":
            get_top_destinations(dataframe),

        "bytes_per_protocol":
            get_bytes_per_protocol(dataframe)

    }

