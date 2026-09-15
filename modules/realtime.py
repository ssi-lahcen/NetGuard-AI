"""
==================================================
NetGuard-AI
Real-Time Monitoring Engine
==================================================

Watches network, authentication, DNS, and beacon
log files for new events and runs the existing
NetGuard-AI detection engines.

Author:
    Lahcen Elkadi
"""

import time

from config import (
    NETWORK_LOG_FILE,
    AUTH_LOG_FILE,
    BEACON_LOG_FILE,
)

from modules.parser import parse_logs
from modules.port_scan import detect_port_scans
from modules.threat_intel import detect_malicious_ips
from modules.brute_force import detect_brute_force
from modules.dns_tunneling import detect_dns_tunneling
from modules.beaconing import detect_beaconing


# ==================================================
# Configuration
# ==================================================

POLL_INTERVAL = 2

DNS_LOG_FILE = "logs/dns_logs.csv"


# ==================================================
# Display Helpers
# ==================================================

def display_port_scan_alert(alert):
    print()
    print("=" * 60)
    print("🚨 REAL-TIME SECURITY ALERT")
    print("=" * 60)

    print("Type       : PORT SCAN")
    print(f"Risk       : {alert['risk']}")
    print(f"Source IP  : {alert['source_ip']}")
    print(f"Target IP  : {alert['destination_ip']}")
    print(f"Ports      : {alert['unique_ports']}")
    print(f"Port List  : {alert['ports']}")

    print("=" * 60)


def display_threat_alert(alert):
    print()
    print("=" * 60)
    print("🚨 REAL-TIME SECURITY ALERT")
    print("=" * 60)

    print("Type       : MALICIOUS IP")
    print(f"Risk       : {alert['risk']}")
    print(f"Matched IP : {alert['matched_ip']}")
    print(f"Direction  : {alert['direction']}")
    print(f"Connections: {alert['connections']}")
    print(f"Feed       : {alert['feed']}")

    print("=" * 60)


def display_brute_force_alert(alert):
    print()
    print("=" * 60)
    print("🚨 REAL-TIME SECURITY ALERT")
    print("=" * 60)

    print("Type       : BRUTE FORCE")
    print(f"Risk       : {alert['risk']}")
    print(f"Source IP  : {alert['source_ip']}")
    print(f"Target IP  : {alert['destination_ip']}")
    print(f"Service    : {alert['service']}")
    print(f"Attempts   : {alert['failed_attempts']}")
    print(f"Successful : {alert['successful_login']}")

    print("=" * 60)


def display_dns_tunneling_alert(alert):
    print()
    print("=" * 60)
    print("🚨 REAL-TIME SECURITY ALERT")
    print("=" * 60)

    print("Type       : DNS TUNNELING")
    print(f"Risk       : {alert['risk']}")
    print(f"Source IP  : {alert['source_ip']}")
    print(f"Queries    : {alert['query_count']}")
    print(f"Longest    : {alert['longest_query']}")

    print()
    print("Suspicious Queries:")

    for query in alert["suspicious_queries"]:
        print(f"  - {query}")

    print("=" * 60)


def display_beaconing_alert(alert):
    print()
    print("=" * 60)
    print("🚨 REAL-TIME SECURITY ALERT")
    print("=" * 60)

    print("Type       : BEACONING")
    print(f"Risk       : {alert['risk']}")
    print(f"Source IP  : {alert['source_ip']}")
    print(f"Target IP  : {alert['destination_ip']}")
    print(f"Events     : {alert['events']}")
    print(f"Avg Interval : {alert['average_interval']}")
    print(f"Std Deviation: {alert['std_deviation']}")

    print("=" * 60)


# ==================================================
# Detection
# ==================================================

def run_realtime_detection(dataframe):
    """
    Run network detection engines.
    """

    port_scan_alerts = detect_port_scans(
        dataframe
    )

    threat_alerts = detect_malicious_ips(
        dataframe
    )

    return (
        port_scan_alerts,
        threat_alerts,
    )


def run_auth_detection(dataframe):
    """
    Run authentication detection engines.
    """

    return detect_brute_force(
        dataframe
    )


def run_dns_detection(dataframe):
    """
    Run DNS tunneling detection.
    """

    return detect_dns_tunneling(
        dataframe
    )


def run_beacon_detection(dataframe):
    """
    Run beaconing detection.
    """

    return detect_beaconing(
        dataframe
    )


# ==================================================
# Real-Time Monitor
# ==================================================

def monitor_network_log(
    log_file=NETWORK_LOG_FILE,
    interval=POLL_INTERVAL,
):
    """
    Monitor network, authentication, DNS, and
    beacon logs for new events.
    """

    print("=" * 60)
    print("🛡️  NetGuard-AI Real-Time Monitor")
    print("=" * 60)

    print(f"Network Log : {log_file}")
    print(f"Auth Log    : {AUTH_LOG_FILE}")
    print(f"DNS Log     : {DNS_LOG_FILE}")
    print(f"Beacon Log  : {BEACON_LOG_FILE}")
    print(f"Interval    : {interval} seconds")
    print()
    print("Waiting for new events...")
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    # ==================================================
    # Initial Row Counts
    # ==================================================

    network_dataframe = parse_logs(
        log_file,
        schema="network",
        verbose=False
    )

    auth_dataframe = parse_logs(
        AUTH_LOG_FILE,
        schema="auth",
        verbose=False
    )

    dns_dataframe = parse_logs(
        DNS_LOG_FILE,
        schema="dns",
        verbose=False
    )

    beacon_dataframe = parse_logs(
        BEACON_LOG_FILE,
        schema="beacon",
        verbose=False
    )

    last_network_row_count = len(
        network_dataframe
    )

    last_auth_row_count = len(
        auth_dataframe
    )

    last_dns_row_count = len(
        dns_dataframe
    )

    last_beacon_row_count = len(
        beacon_dataframe
    )

    # ==================================================
    # Already Detected Alerts
    # ==================================================

    detected_port_scans = set()
    detected_threats = set()
    detected_brute_force = set()
    detected_dns_tunneling = set()
    detected_beaconing = set()

    try:

        while True:

            # ==================================================
            # NETWORK LOG MONITORING
            # ==================================================

            network_dataframe = parse_logs(
                log_file,
                schema="network",
                verbose=False
            )

            current_network_row_count = len(
                network_dataframe
            )

            if current_network_row_count > last_network_row_count:

                new_events = (
                    current_network_row_count
                    - last_network_row_count
                )

                print()
                print(
                    f"📡 New network events: "
                    f"{new_events}"
                )

                (
                    port_scan_alerts,
                    threat_alerts,
                ) = run_realtime_detection(
                    network_dataframe
                )

                for alert in port_scan_alerts:

                    alert_key = (
                        alert["source_ip"],
                        alert["destination_ip"],
                        tuple(alert["ports"]),
                    )

                    if alert_key in detected_port_scans:
                        continue

                    detected_port_scans.add(
                        alert_key
                    )

                    display_port_scan_alert(
                        alert
                    )

                for alert in threat_alerts:

                    alert_key = (
                        alert["matched_ip"],
                        alert["direction"],
                    )

                    if alert_key in detected_threats:
                        continue

                    detected_threats.add(
                        alert_key
                    )

                    display_threat_alert(
                        alert
                    )

                last_network_row_count = (
                    current_network_row_count
                )

            # ==================================================
            # AUTHENTICATION LOG MONITORING
            # ==================================================

            auth_dataframe = parse_logs(
                AUTH_LOG_FILE,
                schema="auth",
                verbose=False
            )

            current_auth_row_count = len(
                auth_dataframe
            )

            if current_auth_row_count > last_auth_row_count:

                new_auth_events = (
                    current_auth_row_count
                    - last_auth_row_count
                )

                print()
                print(
                    f"🔐 New authentication events: "
                    f"{new_auth_events}"
                )

                brute_force_alerts = (
                    run_auth_detection(
                        auth_dataframe
                    )
                )

                for alert in brute_force_alerts:

                    alert_key = (
                        alert["source_ip"],
                        alert["destination_ip"],
                        alert["service"],
                    )

                    if alert_key in detected_brute_force:
                        continue

                    detected_brute_force.add(
                        alert_key
                    )

                    display_brute_force_alert(
                        alert
                    )

                last_auth_row_count = (
                    current_auth_row_count
                )

            # ==================================================
            # DNS LOG MONITORING
            # ==================================================

            dns_dataframe = parse_logs(
                DNS_LOG_FILE,
                schema="dns",
                verbose=False
            )

            current_dns_row_count = len(
                dns_dataframe
            )

            if current_dns_row_count > last_dns_row_count:

                new_dns_events = (
                    current_dns_row_count
                    - last_dns_row_count
                )

                print()
                print(
                    f"🌐 New DNS events: "
                    f"{new_dns_events}"
                )

                dns_alerts = run_dns_detection(
                    dns_dataframe
                )

                for alert in dns_alerts:

                    alert_key = (
                        alert["source_ip"],
                        alert["query_count"],
                        alert["longest_query"],
                    )

                    if alert_key in detected_dns_tunneling:
                        continue

                    detected_dns_tunneling.add(
                        alert_key
                    )

                    display_dns_tunneling_alert(
                        alert
                    )

                last_dns_row_count = (
                    current_dns_row_count
                )

            # ==================================================
            # BEACON LOG MONITORING
            # ==================================================

            beacon_dataframe = parse_logs(
                BEACON_LOG_FILE,
                schema="beacon",
                verbose=False
            )

            current_beacon_row_count = len(
                beacon_dataframe
            )

            if current_beacon_row_count > last_beacon_row_count:

                new_beacon_events = (
                    current_beacon_row_count
                    - last_beacon_row_count
                )

                print()
                print(
                    f"📶 New beacon events: "
                    f"{new_beacon_events}"
                )

                beacon_alerts = run_beacon_detection(
                    beacon_dataframe
                )

                for alert in beacon_alerts:

                    alert_key = (
                        alert["source_ip"],
                        alert["destination_ip"],
                        alert["events"],
                    )

                    if alert_key in detected_beaconing:
                        continue

                    detected_beaconing.add(
                        alert_key
                    )

                    display_beaconing_alert(
                        alert
                    )

                last_beacon_row_count = (
                    current_beacon_row_count
                )

            time.sleep(interval)

    except KeyboardInterrupt:

        print()
        print()
        print("=" * 60)
        print("🛑 Real-Time Monitor stopped.")
        print("=" * 60)


# ==================================================
# Main
# ==================================================

if __name__ == "__main__":

    monitor_network_log()
