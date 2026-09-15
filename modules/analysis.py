"""
==================================================
NetGuard-AI
Analysis Engine
==================================================

Central analysis pipeline used by the CLI and
dashboard.

This module coordinates the existing detection
engines. It does not implement detection logic.
"""

from config import (
    NETWORK_LOG_FILE,
    AUTH_LOG_FILE,
    BEACON_LOG_FILE,
)

from modules.parser import parse_logs

from modules.statistics import (
    build_network_profile,
)

from modules.geoip import (
    enrich_dataframe,
)

from modules.port_scan import (
    detect_port_scans,
)

from modules.brute_force import (
    detect_brute_force,
)

from modules.dns_tunneling import (
    detect_dns_tunneling,
)

from modules.beaconing import (
    detect_beaconing,
)

from modules.threat_intel import (
    detect_malicious_ips,
)


def run_analysis():
    """
    Run the complete NetGuard-AI analysis pipeline.

    Returns:
        dict: All analysis results.
    """

    # ==================================================
    # Network Analysis
    # ==================================================

    network_dataframe = parse_logs(
        NETWORK_LOG_FILE,
        schema="network"
    )

    network_dataframe = enrich_dataframe(
        network_dataframe
    )

    network_profile = build_network_profile(
        network_dataframe
    )

    # ==================================================
    # Port Scan Detection
    # ==================================================

    port_scan_alerts = detect_port_scans(
        network_dataframe
    )

    # ==================================================
    # Authentication Analysis
    # ==================================================

    auth_dataframe = parse_logs(
        AUTH_LOG_FILE,
        schema="auth"
    )

    brute_force_alerts = detect_brute_force(
        auth_dataframe
    )

    # ==================================================
    # DNS Analysis
    # ==================================================

    dns_dataframe = parse_logs(
        "logs/dns_logs.csv",
        schema="dns"
    )

    dns_alerts = detect_dns_tunneling(
        dns_dataframe
    )

    # ==================================================
    # Beaconing Detection
    # ==================================================

    beacon_dataframe = parse_logs(
        BEACON_LOG_FILE,
        schema="beacon"
    )

    beacon_alerts = detect_beaconing(
        beacon_dataframe
    )

    # ==================================================
    # Threat Intelligence
    # ==================================================

    threat_alerts = detect_malicious_ips(
        network_dataframe
    )

    # ==================================================
    # Return Complete Analysis
    # ==================================================

    return {
        "network_dataframe": network_dataframe,
        "network_profile": network_profile,

        "port_scan_alerts": port_scan_alerts,

        "brute_force_alerts": brute_force_alerts,

        "dns_alerts": dns_alerts,

        "beacon_alerts": beacon_alerts,

        "threat_alerts": threat_alerts,
    }

