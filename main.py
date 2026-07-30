"""
==================================================
NetGuard-AI
Main Application
==================================================

Author : Lahcen Elkadi
Description:
    Main entry point for NetGuard-AI.

Workflow:

1. Load network logs
2. Parse and validate logs
3. Build network statistics
4. Display statistics
5. Detect port scans
6. Display alerts

Future modules:

- Brute Force Detection
- DNS Tunneling Detection
- Beaconing Detection
- Threat Intelligence
- GeoIP
- Machine Learning
- Reporting
- Dashboard
==================================================
"""
from modules.beaconing import (
    detect_beaconing,
)
from config import (
    LOG_FILE,
    AUTH_LOG_FILE,
    BEACON_LOG_FILE,
)

from config import (
    LOG_FILE,
    NETWORK_LOG_FILE,
    AUTH_LOG_FILE,
)
from modules.dns_tunneling import (
    detect_dns_tunneling,
)

from modules.brute_force import (
    detect_brute_force,
)

from modules.parser import parse_logs

from modules.statistics import (
    build_network_profile,
)

from modules.port_scan import (
    detect_port_scans,
)


# ==================================================
# Display Network Statistics
# ==================================================

def display_statistics(profile):
    """
    Display network statistics.
    """

    basic = profile["basic_statistics"]

    top_talkers = profile["top_talkers"]

    top_ports = profile["top_ports"]

    protocols = profile["protocol_distribution"]

    print("\nNETWORK STATISTICS")
    print("-" * 50)

    print(f"Total Events            : {basic['total_events']}")
    print(f"Unique Source IPs       : {basic['unique_source_ips']}")
    print(f"Unique Destination IPs  : {basic['unique_destination_ips']}")
    print(f"Unique Ports            : {basic['unique_ports']}")
    print(f"Unique Protocols        : {basic['unique_protocols']}")
    print(f"Total Bytes             : {basic['total_bytes']}")

    print("\nTOP TALKERS")
    print("-" * 50)

    for ip, events in top_talkers.items():

        print(f"{ip:<20} {events} events")

    print("\nTOP DESTINATION PORTS")
    print("-" * 50)

    for port, events in top_ports.items():

        print(f"Port {port:<15} {events} events")

    print("\nPROTOCOL DISTRIBUTION")
    print("-" * 50)

    for protocol, events in protocols.items():
        print(f"{protocol:<20} {events} events")
    
    print("\nTOP DESTINATION IPS")
    print("-" * 50)
    for ip, events in profile["top_destinations"].items():
	    print(f"{ip:<20} {events} events")
    
    print("\nTRAFFIC BY PROTOCOL")
    print("-" * 50)
    for protocol, total_bytes in profile["bytes_per_protocol"].items():
    	print(f"{protocol:<20} {total_bytes} bytes")
# ==================================================
# Display Port Scan Alerts
# ==================================================

def display_port_scan_alerts(alerts):
    """
    Display Port Scan alerts.
    """

    print()
    print("=" * 50)
    print("PORT SCAN DETECTION")
    print("=" * 50)

    if not alerts:

        print("No port scan detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print()
        print(f"Alert #{index}")
        print("-" * 50)

        print(f"Alert Type      : {alert['alert_type']}")
        print(f"Source IP       : {alert['source_ip']}")
        print(f"Destination IP  : {alert['destination_ip']}")
        print(f"Unique Ports    : {alert['unique_ports']}")
        print(f"Risk Level      : {alert['risk']}")

        ports = ", ".join(
            map(str, alert["ports"])
        )

        print(f"Ports           : {ports}")

# ==================================================
# Display DNS Tunneling Alerts
# ==================================================

def display_dns_alerts(alerts):
    """
    Display DNS tunneling alerts.
    """

    print()
    print("=" * 50)
    print("DNS TUNNELING DETECTION")
    print("=" * 50)

    if not alerts:

        print("No DNS tunneling detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print()
        print(f"Alert #{index}")
        print("-" * 50)

        print(f"Source IP       : {alert['source_ip']}")
        print(f"DNS Requests    : {alert['query_count']}")
        print(f"Longest Query   : {alert['longest_query']} characters")
        print(f"Risk Level      : {alert['risk']}")

        print("\nSuspicious Queries:")

        for query in alert["suspicious_queries"]:

            print(f"  - {query}")
        print()

def display_brute_force_alerts(alerts):
    print("=" * 50)
    print("BRUTE FORCE DETECTION")
    print("=" * 50)

    if not alerts:
        print("No brute force attack detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print()
        print(f"Alert #{index}")
        print("-" * 50)

        print(f"Source IP       : {alert['source_ip']}")
        print(f"Destination IP  : {alert['destination_ip']}")
        print(f"Service         : {alert['service']}")
        print(f"Failed Attempts : {alert['failed_attempts']}")
        print(f"Compromised     : {alert['successful_login']}")
        print(f"Risk Level      : {alert['risk']}")
        print(f"First Attempt   : {alert['first_attempt']}")
        print(f"Last Attempt    : {alert['last_attempt']}")
        print(f"Duration        : {alert['duration_seconds']} seconds")


def display_beaconing_alerts(alerts):
    """
    Display Beaconing Detection alerts.
    """

    print()
    print("=" * 50)
    print("BEACONING DETECTION")
    print("=" * 50)

    if not alerts:
        print("No beaconing detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print()
        print(f"Alert #{index}")
        print("-" * 50)

        print(f"Source IP         : {alert['source_ip']}")
        print(f"Destination IP    : {alert['destination_ip']}")
        print(f"Events            : {alert['events']}")
        print(f"Average Interval  : {alert['average_interval']} seconds")
        print(f"Std Deviation     : {alert['std_deviation']}")
        print(f"Risk Level        : {alert['risk']}")
# ==================================================
# Main
# ==================================================

def main():
    """
    NetGuard-AI main workflow.
    """

    print("=" * 50)
    print("NetGuard-AI")
    print("=" * 50)

    # ------------------------------------------
    # Load Logs
    # ------------------------------------------

    network_dataframe = parse_logs(
    NETWORK_LOG_FILE,
    schema="network"
    )
    print("\nLogs loaded successfully.")

    # ------------------------------------------
    # Statistics
    # ------------------------------------------

    network_profile = build_network_profile(
        network_dataframe
    )

    display_statistics(network_profile)

    # ------------------------------------------
    # Port Scan Detection
    # ------------------------------------------

    alerts = detect_port_scans(
        network_dataframe
    )

    display_port_scan_alerts(alerts)

    # ==================================================
    # Authentication Log Analysis
    # ==================================================
    print()
    print("=" * 50)
    print("AUTHENTICATION ANALYSIS")
    print("=" * 50)
    auth_dataframe = parse_logs(
        AUTH_LOG_FILE,
        schema="auth"
    )
    brute_force_alerts = detect_brute_force(
        auth_dataframe
    )
    display_brute_force_alerts(
        brute_force_alerts
    )
    # ------------------------------------------
    # DNS Analysis
    # ------------------------------------------
    print()
    print("=" * 50)
    print("DNS ANALYSIS")
    print("=" * 50)

    dns_dataframe = parse_logs(
        "logs/dns_logs.csv",
        schema="dns"
    )
    dns_alerts = detect_dns_tunneling(
        dns_dataframe
    )
    display_dns_alerts(
        dns_alerts
    )

    # ------------------------------------------
    # Beaconing Detection
    # ------------------------------------------

    print()
    print("=" * 50)
    print("BEACONING ANALYSIS")
    print("=" * 50)

    beacon_dataframe = parse_logs(
        BEACON_LOG_FILE,
        schema="beacon"
    )
    beacon_alerts = detect_beaconing(
        beacon_dataframe
    )
    display_beaconing_alerts(
        beacon_alerts
    )
# ==================================================
# Program Entry
# ==================================================

if __name__ == "__main__":
    main()
