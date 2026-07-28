"""
==================================================
NetGuard-AI
DNS Tunneling Demo
==================================================

Demonstration of the DNS Tunneling Detection Engine.

Author:
    Lahcen Elkadi
"""

from modules.parser import parse_logs
from modules.dns_tunneling import detect_dns_tunneling


DATASET = "logs/dns_logs.csv"


def main():
    """
    Demonstrate DNS tunneling detection.
    """

    print("=" * 50)
    print("DNS TUNNELING TEST")
    print("=" * 50)

    dataframe = parse_logs(
        DATASET,
        schema="dns"
    )

    print("\nDataset loaded successfully.\n")

    alerts = detect_dns_tunneling(
        dataframe
    )

    print(f"Alerts Found: {len(alerts)}")
    print()

    if not alerts:

        print("No DNS tunneling detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print(f"Alert #{index}")
        print("-" * 50)

        print(f"Type            : {alert['alert_type']}")
        print(f"Source IP       : {alert['source_ip']}")
        print(f"DNS Requests    : {alert['query_count']}")
        print(f"Longest Query   : {alert['longest_query']} characters")
        print(f"Risk Level      : {alert['risk']}")

        print("\nSuspicious Queries:")

        for query in alert["suspicious_queries"]:

            print(f"  - {query}")

        print()


if __name__ == "__main__":
    main()
