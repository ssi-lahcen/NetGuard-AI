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

from config import DATA_DIR
from modules.geoip import enrich_ip


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
    Detect communication with known malicious IPs
    and enrich the resulting alerts with GeoIP data.
    """

    malicious_ips = load_malicious_ips()

    whitelist = load_whitelist()

    alerts = {}

    for _, row in dataframe.iterrows():

        src_ip = row["src_ip"]

        dst_ip = row["dst_ip"]

        # --------------------------------------------------
        # Ignore trusted systems
        # --------------------------------------------------

        if src_ip in whitelist:

            continue

        if dst_ip in whitelist:

            continue

        # --------------------------------------------------
        # Check source and destination IPs
        # --------------------------------------------------

        for matched_ip, direction in [
            (src_ip, "SOURCE"),
            (dst_ip, "DESTINATION")
        ]:

            if matched_ip not in malicious_ips:

                continue

            # --------------------------------------------------
            # Create alert
            # --------------------------------------------------

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

            # --------------------------------------------------
            # Update alert
            # --------------------------------------------------

            alert["connections"] += 1

            alert["last_seen"] = row["timestamp"]

            alert["source_ips"].add(src_ip)

            alert["destination_ips"].add(dst_ip)

    # ==================================================
    # GeoIP Enrichment + Set Conversion
    # ==================================================

    for alert in alerts.values():

        alert["source_ips"] = sorted(
            alert["source_ips"]
        )

        alert["destination_ips"] = sorted(
            alert["destination_ips"]
        )

        # --------------------------------------------------
        # Source GeoIP information
        # --------------------------------------------------

        source_countries = set()

        source_cities = set()

        for ip in alert["source_ips"]:

            geoip = enrich_ip(ip)

            source_countries.add(
                geoip["country"]
            )

            source_cities.add(
                geoip["city"]
            )

        alert["source_countries"] = sorted(
            source_countries
        )

        alert["source_cities"] = sorted(
            source_cities
        )

        # --------------------------------------------------
        # Destination GeoIP information
        # --------------------------------------------------

        destination_countries = set()

        destination_cities = set()

        for ip in alert["destination_ips"]:

            geoip = enrich_ip(ip)

            destination_countries.add(
                geoip["country"]
            )

            destination_cities.add(
                geoip["city"]
            )

        alert["destination_countries"] = sorted(
            destination_countries
        )

        alert["destination_cities"] = sorted(
            destination_cities
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
