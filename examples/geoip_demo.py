"""
==================================================
NetGuard-AI
GeoIP Demo
==================================================

Demonstrates the GeoIP enrichment engine.

Author:
    Lahcen Elkadi
"""

from modules.geoip import (
    enrich_ip,
    enrich_dataframe
)

from modules.parser import parse_logs


# ==================================================
# IP Lookup Demo
# ==================================================

def display_ip_lookup(ip_address: str) -> None:
    """
    Display GeoIP information for an IP address.
    """

    result = enrich_ip(ip_address)

    print(f"IP Address : {result['ip']}")
    print(f"Country    : {result['country']}")
    print(f"City       : {result['city']}")


# ==================================================
# Main Demo
# ==================================================

def main() -> None:

    print("=" * 50)
    print("GEOIP ENRICHMENT DEMO")
    print("=" * 50)

    # --------------------------------------------------
    # Test 1: Known public IP
    # --------------------------------------------------

    print()
    print("Test 1 - Known Public IP")
    print("-" * 50)

    display_ip_lookup(
        "45.77.12.8"
    )

    # --------------------------------------------------
    # Test 2: Private IP
    # --------------------------------------------------

    print()
    print("Test 2 - Private IP")
    print("-" * 50)

    display_ip_lookup(
        "192.168.1.5"
    )

    # --------------------------------------------------
    # Test 3: Unknown public IP
    # --------------------------------------------------

    print()
    print("Test 3 - Unknown Public IP")
    print("-" * 50)

    display_ip_lookup(
        "123.123.123.123"
    )

    # --------------------------------------------------
    # Test 4: Invalid IP
    # --------------------------------------------------

    print()
    print("Test 4 - Invalid IP")
    print("-" * 50)

    display_ip_lookup(
        "abc"
    )

    # --------------------------------------------------
    # Test 5: Network log enrichment
    # --------------------------------------------------

    print()
    print("Test 5 - Network Log Enrichment")
    print("-" * 50)

    dataframe = parse_logs(
        "logs/network_logs.csv",
        schema="network"
    )

    enriched_dataframe = enrich_dataframe(
        dataframe
    )

    print(
        enriched_dataframe[
            [
                "src_ip",
                "src_country",
                "src_city",
                "dst_ip",
                "dst_country",
                "dst_city"
            ]
        ].to_string(index=False)
    )


# ==================================================
# Entry Point
# ==================================================

if __name__ == "__main__":

    main()
