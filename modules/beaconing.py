"""
==================================================
NetGuard-AI
Beaconing Detection Module
==================================================

Detect periodic network communication that may
indicate Command & Control (C2) beaconing.

Author:
    Lahcen Elkadi
"""

import pandas as pd

from config import (
    BEACON_MIN_EVENTS,
    BEACON_STD_THRESHOLD,
)
# ==================================================
# Risk Classification
# ==================================================

def classify_risk(
    std_deviation: float,
    events: int
) -> str:
    """
    Classify beaconing risk.
    """

    if events >= 20 and std_deviation <= 2:
        return "CRITICAL"

    if events >= 10 and std_deviation <= 5:
        return "HIGH"

    if events >= BEACON_MIN_EVENTS:
        return "MEDIUM"

    return "LOW"

# ==================================================
# Beaconing Detection
# ==================================================

def detect_beaconing(
    dataframe: pd.DataFrame
) -> list:
    """
    Detect periodic communications.
    """

    alerts = []

    dataframe = dataframe.sort_values(
        "timestamp"
    )

    grouped = dataframe.groupby(
        [
            "src_ip",
            "dst_ip"
        ]
    )

    for (
        src_ip,
        dst_ip
    ), group in grouped:

        if len(group) < BEACON_MIN_EVENTS:
            continue

        group = group.sort_values(
            "timestamp"
        )

        intervals = (
            group["timestamp"]
            .diff()
            .dt.total_seconds()
            .dropna()
        )

        if len(intervals) == 0:
            continue

        average_interval = intervals.mean()

        std_deviation = intervals.std()

        if pd.isna(std_deviation):
            std_deviation = 0

        if std_deviation > BEACON_STD_THRESHOLD:
            continue

        alerts.append({

            "alert_type":
                "BEACONING",

            "source_ip":
                src_ip,

            "destination_ip":
                dst_ip,

            "events":
                len(group),

            "average_interval":
                round(
                    average_interval,
                    2
                ),

            "std_deviation":
                round(
                    std_deviation,
                    2
                ),

            "risk":
                classify_risk(
                    std_deviation,
                    len(group)
                )

        })

    return alerts
