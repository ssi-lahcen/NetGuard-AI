"""
==================================================
NetGuard-AI
Brute Force Detection Module
==================================================

Detect repeated failed authentication attempts.

Author:
    Lahcen Elkadi
"""

import pandas as pd

from config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_TIME_WINDOW,
    HIGH_ATTEMPTS,
    CRITICAL_ATTEMPTS,
)

# ==================================================
# Risk Classification
# ==================================================
def classify_risk(
    attempts: int,
    compromised: bool
) -> str:
    """
    Assign a risk level.
    """

    if compromised:
        return "CRITICAL"

    if attempts >= CRITICAL_ATTEMPTS:
        return "CRITICAL"

    if attempts >= HIGH_ATTEMPTS:
        return "HIGH"

    if attempts >= BRUTE_FORCE_THRESHOLD:
        return "MEDIUM"

    return "LOW"     

# ==================================================
# Detection Engine
# ==================================================

def detect_brute_force(
    dataframe: pd.DataFrame
) -> list:
    """
    Detect brute force attacks.
    """

    alerts = []

    failed = dataframe[
        dataframe["status"] == "FAILED"
    ]

    failed = failed.sort_values(
        by="timestamp"
    )

    grouped = failed.groupby(
        [
            "src_ip",
            "dst_ip",
            "service"
        ]
    )

    for (
        src_ip,
        dst_ip,
        service
    ), group in grouped:

        attempts = len(group)
        first_attempt = group["timestamp"].min()
        last_attempt = group["timestamp"].max()
        attack_duration = (
            last_attempt - first_attempt
        ).total_seconds()

        success_after_failures = (
                dataframe[
                    (dataframe["src_ip"] == src_ip)
                    &
                    (dataframe["dst_ip"] == dst_ip)
                    &
                    (dataframe["service"] == service)
                    &
                    (dataframe["status"] == "SUCCESS")
                ].shape[0] > 0
        )

        if attempts < BRUTE_FORCE_THRESHOLD:
            continue

        if attack_duration > BRUTE_FORCE_TIME_WINDOW:
            continue

        alerts.append({

            "alert_type":
                "BRUTE_FORCE",

            "source_ip":
                src_ip,

            "destination_ip":
                dst_ip,

            "service":
                service,

            "failed_attempts":
                attempts,

            "successful_login":
                success_after_failures,

            "risk":
                classify_risk(
                    attempts,
                    success_after_failures
                ),
            "first_attempt":
                first_attempt,

            "last_attempt":
                last_attempt,

            "duration_seconds":
                attack_duration,

        })

    return alerts
