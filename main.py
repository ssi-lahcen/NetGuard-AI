"""
NetGuard-AI

Main entry point.
"""

from config import LOG_FILE
from modules.parser import parse_logs
from modules.statistics import calculate_basic_statistics


def main():
    """
    Start the NetGuard-AI application.
    """

    print("=" * 50)
    print("NetGuard-AI")
    print("=" * 50)

    dataframe = parse_logs(LOG_FILE)

    print("\nLogs loaded successfully.\n")

    statistics = calculate_basic_statistics(
        dataframe
    )

    print("NETWORK STATISTICS")
    print("-" * 50)

    print(
        f"Total Events       : "
        f"{statistics['total_events']}"
    )

    print(
        f"Unique Source IPs  : "
        f"{statistics['unique_source_ips']}"
    )

    print(
        f"Unique Destination IPs: "
        f"{statistics['unique_destination_ips']}"
    )

    print(
        f"Unique Ports       : "
        f"{statistics['unique_ports']}"
    )

    print(
        f"Unique Protocols    : "
        f"{statistics['unique_protocols']}"
    )

    print(
        f"Total Bytes        : "
        f"{statistics['total_bytes']}"
    )


if __name__ == "__main__":
    main()
