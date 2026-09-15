"""
==================================================
NetGuard-AI
Alert Normalization Engine
==================================================

Converts the different detector outputs into one
standardized alert structure for the dashboard.
"""


def normalize_port_scan(alert):
    """Normalize a port scan alert."""

    return {
        "alert_type": "PORT_SCAN",
        "severity": alert["risk"],
        "source_ip": alert["source_ip"],
        "destination_ip": alert["destination_ip"],
        "summary": (
            f"Port scan detected against "
            f"{alert['destination_ip']}"
        ),
        "details": {
            "unique_ports": alert["unique_ports"],
            "ports": alert["ports"],
        },
    }


def normalize_brute_force(alert):
    """Normalize a brute-force alert."""

    service = alert["service"]

    return {
        "alert_type": "BRUTE_FORCE",
        "severity": alert["risk"],
        "source_ip": alert["source_ip"],
        "destination_ip": alert["destination_ip"],
        "summary": (
            f"{service} brute force attack detected"
        ),
        "details": {
            "service": service,
            "failed_attempts": alert["failed_attempts"],
            "successful_login": alert["successful_login"],
            "first_attempt": alert["first_attempt"],
            "last_attempt": alert["last_attempt"],
            "duration_seconds": alert["duration_seconds"],
        },
    }


def normalize_dns_tunneling(alert):
    """Normalize a DNS tunneling alert."""

    return {
        "alert_type": "DNS_TUNNELING",
        "severity": alert["risk"],
        "source_ip": alert["source_ip"],
        "destination_ip": None,
        "summary": "Potential DNS tunneling detected",
        "details": {
            "query_count": alert["query_count"],
            "longest_query": alert["longest_query"],
            "suspicious_queries": alert["suspicious_queries"],
        },
    }


def normalize_beaconing(alert):
    """Normalize a beaconing alert."""

    return {
        "alert_type": "BEACONING",
        "severity": alert["risk"],
        "source_ip": alert["source_ip"],
        "destination_ip": alert["destination_ip"],
        "summary": (
            f"Potential beaconing detected "
            f"to {alert['destination_ip']}"
        ),
        "details": {
            "events": alert["events"],
            "average_interval": alert["average_interval"],
            "std_deviation": alert["std_deviation"],
        },
    }


def normalize_threat_intel(alert):
    """Normalize a threat intelligence alert."""

    return {
        "alert_type": "MALICIOUS_IP",
        "severity": alert["risk"],
        "source_ip": (
            alert["source_ips"][0]
            if alert["source_ips"]
            else None
        ),
        "destination_ip": (
            alert["destination_ips"][0]
            if alert["destination_ips"]
            else None
        ),
        "summary": (
            f"Malicious IP detected: "
            f"{alert['matched_ip']}"
        ),
        "details": {
            "matched_ip": alert["matched_ip"],
            "direction": alert["direction"],
            "connections": alert["connections"],
            "first_seen": alert["first_seen"],
            "last_seen": alert["last_seen"],
            "source_ips": alert["source_ips"],
            "destination_ips": alert["destination_ips"],
            "feed": alert["feed"],
        },
    }


def normalize_alerts(
    port_scan_alerts,
    brute_force_alerts,
    dns_alerts,
    beacon_alerts,
    threat_alerts,
):
    """
    Normalize all detector alerts into one list.

    Returns:
        list: Standardized NetGuard-AI alerts.
    """

    normalized_alerts = []

    for alert in port_scan_alerts:
        normalized_alerts.append(
            normalize_port_scan(alert)
        )

    for alert in brute_force_alerts:
        normalized_alerts.append(
            normalize_brute_force(alert)
        )

    for alert in dns_alerts:
        normalized_alerts.append(
            normalize_dns_tunneling(alert)
        )

    for alert in beacon_alerts:
        normalized_alerts.append(
            normalize_beaconing(alert)
        )

    for alert in threat_alerts:
        normalized_alerts.append(
            normalize_threat_intel(alert)
        )

    return normalized_alerts
