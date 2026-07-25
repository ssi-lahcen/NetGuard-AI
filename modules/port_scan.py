"""
Port Scan Detection Module

Detects hosts contacting many destination ports.
"""

from config import (
    PORT_SCAN_THRESHOLD,
    LOW_RISK_PORTS,
    MEDIUM_RISK_PORTS,
    HIGH_RISK_PORTS
)


def calculate_risk(unique_ports):
    """
    Calculate severity according to number of ports.
    """

    if unique_ports >= HIGH_RISK_PORTS:
        return "HIGH"

    elif unique_ports >= MEDIUM_RISK_PORTS:
        return "MEDIUM"

    elif unique_ports >= LOW_RISK_PORTS:
        return "LOW"

    return "INFO"


def detect_port_scans(df):
    """
    Detect possible port scans.

    Returns:
        list of alerts
    """

    alerts = []

    grouped = df.groupby("src_ip")

    for source_ip, group in grouped:

        unique_ports = group["dst_port"].nunique()

        if unique_ports >= PORT_SCAN_THRESHOLD:

            destination_ip = group["dst_ip"].mode().iloc[0]

            alert = {

                "alert_type": "PORT_SCAN",

                "source_ip": source_ip,

                "destination_ip": destination_ip,

                "unique_ports": unique_ports,

                "risk": calculate_risk(unique_ports),

                "ports": sorted(group["dst_port"].unique())

            }

            alerts.append(alert)

    return alerts
