"""
==================================================
NetGuard-AI
Threat Intelligence Demo
==================================================

Demonstration of the Threat Intelligence Engine.

Author:
    Lahcen Elkadi
"""

from modules.parser import parse_logs

from modules.threat_intel import (
    detect_malicious_ips,
)

from config import LOG_FILE


def main():
    """
    Demonstrate Threat Intelligence Detection.
    """

    print("=" * 50)
    print("THREAT INTELLIGENCE TEST")
    print("=" * 50)

    dataframe = parse_logs(
        LOG_FILE,
        schema="network"
    )

    print("\nDataset loaded successfully.\n")

    alerts = detect_malicious_ips(
        dataframe
    )

    print(f"Alerts Found: {len(alerts)}")

    print()

    if not alerts:

        print("No malicious IPs detected.")
        return

    for index, alert in enumerate(alerts, start=1):

        print(f"Alert #{index}")
        print("-" * 50)

        print(
            f"Alert Type : {alert['alert_type']}"
        )

        print(
            f"IP Address : {alert['ip']}"
        )

        print(
            f"Direction  : {alert['direction']}"
        )

        print(
            f"Risk Level : {alert['risk']}"
        )

        print()


if __name__ == "__main__":
    main()
