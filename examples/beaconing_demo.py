"""
==================================================
NetGuard-AI
Beaconing Detection Demo
==================================================

Demonstration of the Beaconing Detection Engine.

Author:
    Lahcen Elkadi
"""

from modules.parser import parse_logs
from modules.beaconing import detect_beaconing

DATASET = "logs/beacon_logs.csv"


def main():
    """
    Demonstrate beaconing detection.
    """

    print("=" * 50)
    print("BEACONING TEST")
    print("=" * 50)

    dataframe = parse_logs(
        DATASET,
        schema="beacon"
    )

    print("\nDataset loaded successfully.\n")

    alerts = detect_beaconing(
        dataframe
    )

    print(f"Alerts Found: {len(alerts)}")
    print()

    if not alerts:

        print("No beaconing detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print(f"Alert #{index}")
        print("-" * 50)

        print(f"Type              : {alert['alert_type']}")
        print(f"Source IP         : {alert['source_ip']}")
        print(f"Destination IP    : {alert['destination_ip']}")
        print(f"Events            : {alert['events']}")
        print(f"Average Interval  : {alert['average_interval']} seconds")
        print(f"Std Deviation     : {alert['std_deviation']}")
        print(f"Risk Level        : {alert['risk']}")

        print()


if __name__ == "__main__":
    main()
