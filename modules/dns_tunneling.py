"""
==================================================
NetGuard-AI
DNS Tunneling Detection Module
==================================================

Detect suspicious DNS tunneling activity.

Author:
    Lahcen Elkadi
"""

import re

import pandas as pd

from config import (
    DNS_QUERY_LENGTH_THRESHOLD,
    DNS_REQUEST_THRESHOLD,
)


# ==================================================
# Risk Classification
# ==================================================

def classify_risk(
    query_count: int,
    max_query_length: int
) -> str:
    """
    Assign a risk level.
    """

    if query_count >= 20 or max_query_length >= 120:
        return "CRITICAL"

    if query_count >= 10 or max_query_length >= 80:
        return "HIGH"

    if query_count >= DNS_REQUEST_THRESHOLD:
        return "MEDIUM"

    return "LOW"


# ==================================================
# Base64 Detection
# ==================================================

def looks_like_base64(
    query: str
) -> bool:
    """
    Detect Base64-like strings inside DNS queries.
    """

    pattern = r"[A-Za-z0-9+/=]{20,}"

    return bool(
        re.search(pattern, query)
    )


# ==================================================
# Detection Engine
# ==================================================

def detect_dns_tunneling(
    dataframe: pd.DataFrame
) -> list:
    """
    Detect possible DNS tunneling.
    """

    alerts = []

    grouped = dataframe.groupby("src_ip")

    for src_ip, group in grouped:

        query_count = len(group)

        longest_query = max(
            len(query)
            for query in group["query"]
        )

        suspicious_queries = []

        for query in group["query"]:

            if (
                len(query)
                >= DNS_QUERY_LENGTH_THRESHOLD
                or looks_like_base64(query)
            ):

                suspicious_queries.append(query)

        if (
            query_count < DNS_REQUEST_THRESHOLD
            and len(suspicious_queries) == 0
        ):
            continue

        alerts.append({

            "alert_type":
                "DNS_TUNNELING",

            "source_ip":
                src_ip,

            "query_count":
                query_count,

            "suspicious_queries":
                suspicious_queries,

            "longest_query":
                longest_query,

            "risk":
                classify_risk(
                    query_count,
                    longest_query
                )

        })

    return alerts
