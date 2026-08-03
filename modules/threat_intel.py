"""
==================================================
NetGuard-AI
Threat Intelligence Module
==================================================

Detect communication with known malicious IPs.

Author:
    Lahcen Elkadi
"""

from pathlib import Path

import pandas as pd

from config import (
    DATA_DIR,
)

# ==================================================
# Load Malicious IP Database
# ==================================================

def load_malicious_ips() -> set:
    """
    Load malicious IP addresses from file.
    """

    file_path = DATA_DIR / "malicious_ips.txt"

    malicious_ips = set()

    with open(file_path, "r") as file:

        for line in file:

            ip = line.strip()

            if ip:

                malicious_ips.add(ip)

    return malicious_ips

# ==================================================
# Load Whitelist
# ==================================================

def load_whitelist() -> set:
    """
    Load trusted IP addresses.
    """

    file_path = DATA_DIR / "whitelist.txt"

    whitelist = set()

    with open(file_path, "r") as file:

        for line in file:

            ip = line.strip()

            if ip:

                whitelist.add(ip)

    return whitelist

# ==================================================
# Risk Classification
# ==================================================

def classify_risk(
    malicious: bool
) -> str:
    """
    Classify threat intelligence risk.
    """

    if malicious:
        return "HIGH"

    return "LOW"

# ==================================================
# Threat Intelligence Detection
# ==================================================

def detect_malicious_ips(
    dataframe: pd.DataFrame
) -> list:
    """
    Detect communication with known malicious IPs.
    """

    malicious_ips = load_malicious_ips()

    whitelist = load_whitelist()

    alerts = {}

    for _, row in dataframe.iterrows():

        src_ip = row["src_ip"]

        dst_ip = row["dst_ip"]

        # Ignore trusted systems

        if src_ip in whitelist:

            continue

        if dst_ip in whitelist:

            continue

        for matched_ip, direction in [
            (src_ip, "SOURCE"),
            (dst_ip, "DESTINATION")
        ]:
            if matched_ip not in malicious_ips:
                continue

            if matched_ip not in alerts:
                alerts[matched_ip] = {
                    "alert_type": "MALICIOUS_IP",

                    "matched_ip": matched_ip,

                    "direction": direction,

                    "connections": 0,

                    "first_seen": row["timestamp"],

                    "last_seen": row["timestamp"],

                    "source_ips": set(),

                    "destination_ips": set(),

                    "feed": "Local IOC Database",

                    "risk": classify_risk(True)
                }
            alert = alerts[matched_ip]

            alert["connections"] += 1

            alert["last_seen"] = row["timestamp"]

            alert["source_ips"].add(src_ip)

            alert["destination_ips"].add(dst_ip)
# ==================================================
# Convert sets to lists
# ==================================================

    for alert in alerts.values():

        alert["source_ips"] = sorted(
            alert["source_ips"]
        )

        alert["destination_ips"] = sorted(
            alert["destination_ips"]
        )
    return list(alerts.values())

# ==================================================
# Temporary Test
# ==================================================

if __name__ == "__main__":

    malicious = load_malicious_ips()

    whitelist = load_whitelist()

    print("Malicious IPs")
    print(malicious)

    print()

    print("Whitelist")
    print(whitelist)

