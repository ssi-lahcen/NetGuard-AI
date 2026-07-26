"""
Test Brute Force Detection
"""

from modules.parser import parse_logs
from modules.brute_force import detect_brute_force

DATASET = "datasets/brute_force.csv"


def main():

    print("=" * 50)
    print("BRUTE FORCE TEST")
    print("=" * 50)

    dataframe = parse_logs(
        DATASET,
        schema="auth"
    )

    print("\nDataset loaded successfully.\n")

    alerts = detect_brute_force(
        dataframe
    )

    print(f"Alerts Found: {len(alerts)}")

    print()

    for index, alert in enumerate(alerts, start=1):

        print(f"Alert #{index}")
        print("-" * 40)

        print(f"Type        : {alert['alert_type']}")
        print(f"Source IP   : {alert['source_ip']}")
        print(f"Destination : {alert['destination_ip']}")
        print(f"Service     : {alert['service']}")
        print(f"Attempts    : {alert['failed_attempts']}")
        print(f"Risk        : {alert['risk']}")
        print(f"Compromised : {alert['successful_login']}")
        print(f"First Try   : {alert['first_attempt']}")
        print(f"Last Try    : {alert['last_attempt']}")
        print(f"Duration    : {alert['duration_seconds']} seconds")

        print()


if __name__ == "__main__":
    main()
