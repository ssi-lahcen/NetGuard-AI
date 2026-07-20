"""
NetGuard-AI

Main entry point.
"""

from config import LOG_FILE

from modules.parser import parse_logs

from modules.statistics import (
    build_network_profile,
)


def main():
    """
    Start the NetGuard-AI application.
    """

    print("=" * 50)
    print("NetGuard-AI")
    print("=" * 50)

    dataframe = parse_logs(LOG_FILE)

    print("\nLogs loaded successfully.\n")

    network_profile = build_network_profile(
        dataframe
    )

    basic_statistics = (
        network_profile["basic_statistics"]
    )

    top_talkers = (
        network_profile["top_talkers"]
    )

    top_ports = (
        network_profile["top_ports"]
    )

    protocol_distribution = (
        network_profile[
            "protocol_distribution"
        ]
    )

    print("NETWORK STATISTICS")
    print("-" * 50)

    print(
        f"Total Events       : "
        f"{basic_statistics['total_events']}"
    )

    print(
        f"Unique Source IPs  : "
        f"{basic_statistics['unique_source_ips']}"
    )

    print(
        f"Unique Destination IPs: "
        f"{basic_statistics['unique_destination_ips']}"
    )

    print(
        f"Unique Ports       : "
        f"{basic_statistics['unique_ports']}"
    )

    print(
        f"Unique Protocols    : "
        f"{basic_statistics['unique_protocols']}"
    )

    print(
        f"Total Bytes        : "
        f"{basic_statistics['total_bytes']}"
    )

    print("\nTOP TALKERS")
    print("-" * 50)

    for ip_address, event_count in (
        top_talkers.items()
    ):

        print(
            f"{ip_address:<20}"
            f"{event_count} events"
        )

    print("\nTOP DESTINATION PORTS")
    print("-" * 50)

    for port, event_count in (
        top_ports.items()
    ):

        print(
            f"Port {port:<15}"
            f"{event_count} events"
        )

    print("\nPROTOCOL DISTRIBUTION")
    print("-" * 50)

    for protocol, event_count in (
        protocol_distribution.items()
    ):

        print(
            f"{protocol:<20}"
            f"{event_count} events"
        )


if __name__ == "__main__":
    main()
