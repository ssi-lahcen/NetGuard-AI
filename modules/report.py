"""
==================================================
NetGuard-AI
Security Reporting Module
==================================================

Generate security reports from NetGuard-AI
analysis results.

Author:
    Lahcen Elkadi
"""

from pathlib import Path
from datetime import datetime

# ==================================================
# Risk Summary
# ==================================================

def build_risk_summary(
    port_scan_alerts,
    brute_force_alerts,
    dns_alerts,
    beacon_alerts,
    threat_alerts
):
    """
    Count alerts by risk level.
    """

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    all_alerts = (
        port_scan_alerts
        + brute_force_alerts
        + dns_alerts
        + beacon_alerts
        + threat_alerts
    )

    for alert in all_alerts:

        risk = alert.get(
            "risk",
            "INFO"
        )

        if risk in summary:
            summary[risk] += 1

    return summary

def get_priority_findings(
    port_scan_alerts,
    brute_force_alerts,
    dns_alerts,
    beacon_alerts,
    threat_alerts
):
    """
    Return alerts ordered by risk priority.
    """

    all_alerts = (
        port_scan_alerts
        + brute_force_alerts
        + dns_alerts
        + beacon_alerts
        + threat_alerts
    )

    risk_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    return sorted(
        all_alerts,
        key=lambda alert: risk_order.get(
            alert.get("risk", "INFO"),
            4
        )
    )
# ==================================================
# Report Generation
# ==================================================

def generate_report(
    network_profile,
    port_scan_alerts,
    brute_force_alerts,
    dns_alerts,
    beacon_alerts,
    threat_alerts
):
    """
    Generate a complete NetGuard-AI security report.

    Returns:
        str: formatted security report
    """

    basic = network_profile["basic_statistics"]

    risk_summary = build_risk_summary(
        port_scan_alerts,
        brute_force_alerts,
        dns_alerts,
        beacon_alerts,
        threat_alerts
    )

    total_alerts = sum(
        risk_summary.values()
    )
    priority_findings = get_priority_findings(
        port_scan_alerts,
        brute_force_alerts,
        dns_alerts,
        beacon_alerts,
        threat_alerts
    )
    lines = []
    report_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    # ==================================================
    # Header
    # ==================================================

    lines.append("=" * 70)
    lines.append("NetGuard-AI SECURITY REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(
        f"Report Generated : {report_time}"
    )
    lines.append(
        "Analysis Scope   : Network security log analysis"
    )
    # ==================================================
    # Executive Summary
    # ==================================================

    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 70)

    if risk_summary["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif risk_summary["HIGH"] > 0:
        overall_risk = "HIGH"
    elif risk_summary["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    elif risk_summary["LOW"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    lines.append(
        f"Overall Risk          : {overall_risk}"
    )

    lines.append(
        f"Total Security Alerts : {total_alerts}"
    )

    lines.append(
        f"Critical Alerts       : {risk_summary['CRITICAL']}"
    )
    lines.append(
        f"High Alerts           : {risk_summary['HIGH']}"
    )

    lines.append(
        f"Medium Alerts         : {risk_summary['MEDIUM']}"
    )

    lines.append(
        f"Low Alerts            : {risk_summary['LOW']}"
    )
    # ==================================================
    # Priority Findings
    # ==================================================

    lines.append("")
    lines.append("PRIORITY FINDINGS")
    lines.append("-" * 70)

    if not priority_findings:

        lines.append(
            "No security findings detected."
        )

    else:

        for index, alert in enumerate(
            priority_findings[:3],
            start=1
        ):

            lines.append(
                f"{index}. {alert['alert_type']}"
            )

            lines.append(
                f"   Risk           : "
                f"{alert.get('risk', 'INFO')}"
            )

            if "source_ip" in alert:
                lines.append(
                    f"   Source IP      : "
                    f"{alert['source_ip']}"
                )

            if "destination_ip" in alert:
                lines.append(
                    f"   Destination IP : "
                    f"{alert['destination_ip']}"
                )

            if "service" in alert:
                lines.append(
                    f"   Service        : "
                    f"{alert['service']}"
                )

            if "matched_ip" in alert:
                lines.append(
                    f"   Matched IOC    : "
                    f"{alert['matched_ip']}"
                )
    # ==================================================
    # NETWORK STATISTICS
    # ==================================================

    lines.append("")
    lines.append("NETWORK STATISTICS")
    lines.append("-" * 70)

    lines.append(
        f"Total Events           : "
        f"{basic['total_events']}"
    )

    lines.append(
        f"Unique Source IPs      : "
        f"{basic['unique_source_ips']}"
    )

    lines.append(
        f"Unique Destination IPs : "
        f"{basic['unique_destination_ips']}"
    )

    lines.append(
        f"Unique Ports           : "
        f"{basic['unique_ports']}"
    )

    lines.append(
        f"Unique Protocols       : "
        f"{basic['unique_protocols']}"
    )

    lines.append(
        f"Total Bytes            : "
        f"{basic['total_bytes']}"
    )

    # ==================================================
    # Port Scan Alerts
    # ==================================================

    lines.append("")
    lines.append("PORT SCAN DETECTION")
    lines.append("-" * 70)

    if not port_scan_alerts:

        lines.append(
            "No port scan detected."
        )

    else:

        for index, alert in enumerate(
            port_scan_alerts,
            start=1
        ):

            lines.append(
                f"Alert #{index}"
            )

            lines.append(
                f"  Source IP      : "
                f"{alert['source_ip']}"
            )

            lines.append(
                f"  Destination IP : "
                f"{alert['destination_ip']}"
            )

            lines.append(
                f"  Unique Ports   : "
                f"{alert['unique_ports']}"
            )

            lines.append(
                f"  Risk Level     : "
                f"{alert['risk']}"
            )

            lines.append(
                f"  Ports          : "
                f"{', '.join(map(str, alert['ports']))}"
            )

    # ==================================================
    # Brute Force Alerts
    # ==================================================

    lines.append("")
    lines.append("BRUTE FORCE DETECTION")
    lines.append("-" * 70)

    if not brute_force_alerts:

        lines.append(
            "No brute force attack detected."
        )

    else:

        for index, alert in enumerate(
            brute_force_alerts,
            start=1
        ):

            lines.append(
                f"Alert #{index}"
            )

            lines.append(
                f"  Source IP       : "
                f"{alert['source_ip']}"
            )

            lines.append(
                f"  Destination IP  : "
                f"{alert['destination_ip']}"
            )

            lines.append(
                f"  Service         : "
                f"{alert['service']}"
            )

            lines.append(
                f"  Failed Attempts : "
                f"{alert['failed_attempts']}"
            )

            lines.append(
                f"  Compromised     : "
                f"{alert['successful_login']}"
            )

            lines.append(
                f"  Risk Level      : "
                f"{alert['risk']}"
            )

            lines.append(
                f"  First Attempt   : "
                f"{alert['first_attempt']}"
            )

            lines.append(
                f"  Last Attempt    : "
                f"{alert['last_attempt']}"
            )

            lines.append(
                f"  Duration        : "
                f"{alert['duration_seconds']} seconds"
            )

    # ==================================================
    # DNS Tunneling Alerts
    # ==================================================

    lines.append("")
    lines.append("DNS TUNNELING DETECTION")
    lines.append("-" * 70)

    if not dns_alerts:

        lines.append(
            "No DNS tunneling detected."
        )

    else:

        for index, alert in enumerate(
            dns_alerts,
            start=1
        ):

            lines.append(
                f"Alert #{index}"
            )

            lines.append(
                f"  Source IP     : "
                f"{alert['source_ip']}"
            )

            lines.append(
                f"  DNS Requests  : "
                f"{alert['query_count']}"
            )

            lines.append(
                f"  Longest Query : "
                f"{alert['longest_query']} characters"
            )

            lines.append(
                f"  Risk Level    : "
                f"{alert['risk']}"
            )

            if alert["suspicious_queries"]:

                lines.append(
                    "  Suspicious Queries:"
                )

                for query in alert[
                    "suspicious_queries"
                ]:

                    lines.append(
                        f"    - {query}"
                    )

    # ==================================================
    # Beaconing Alerts
    # ==================================================

    lines.append("")
    lines.append("BEACONING DETECTION")
    lines.append("-" * 70)

    if not beacon_alerts:

        lines.append(
            "No beaconing detected."
        )

    else:

        for index, alert in enumerate(
            beacon_alerts,
            start=1
        ):

            lines.append(
                f"Alert #{index}"
            )

            lines.append(
                f"  Source IP        : "
                f"{alert['source_ip']}"
            )

            lines.append(
                f"  Destination IP   : "
                f"{alert['destination_ip']}"
            )

            lines.append(
                f"  Events           : "
                f"{alert['events']}"
            )

            lines.append(
                f"  Average Interval : "
                f"{alert['average_interval']} seconds"
            )

            lines.append(
                f"  Std Deviation    : "
                f"{alert['std_deviation']}"
            )

            lines.append(
                f"  Risk Level       : "
                f"{alert['risk']}"
            )

    # ==================================================
    # Threat Intelligence Alerts
    # ==================================================

    lines.append("")
    lines.append("THREAT INTELLIGENCE")
    lines.append("-" * 70)

    if not threat_alerts:

        lines.append(
            "No malicious IPs detected."
        )

    else:

        for index, alert in enumerate(
            threat_alerts,
            start=1
        ):

            lines.append(
                f"Alert #{index}"
            )

            lines.append(
                f"  Matched IOC          : "
                f"{alert['matched_ip']}"
            )

            lines.append(
                f"  Direction            : "
                f"{alert['direction']}"
            )

            lines.append(
                f"  Connections          : "
                f"{alert['connections']}"
            )

            lines.append(
                f"  First Seen           : "
                f"{alert['first_seen']}"
            )

            lines.append(
                f"  Last Seen            : "
                f"{alert['last_seen']}"
            )

            lines.append(
                f"  Source IPs           : "
                f"{', '.join(alert['source_ips'])}"
            )

            lines.append(
                f"  Source Countries     : "
                f"{', '.join(alert['source_countries'])}"
            )

            lines.append(
                f"  Source Cities        : "
                f"{', '.join(alert['source_cities'])}"
            )

            lines.append(
                f"  Destination IPs      : "
                f"{', '.join(alert['destination_ips'])}"
            )

            lines.append(
                f"  Destination Countries: "
                f"{', '.join(alert['destination_countries'])}"
            )

            lines.append(
                f"  Destination Cities   : "
                f"{', '.join(alert['destination_cities'])}"
            )

            lines.append(
                f"  Threat Feed          : "
                f"{alert['feed']}"
            )

            lines.append(
                f"  Risk Level           : "
                f"{alert['risk']}"
            )

    # ==================================================
    # Risk Summary
    # ==================================================

    lines.append("")
    lines.append("RISK SUMMARY")
    lines.append("-" * 70)

    for risk, count in risk_summary.items():

        lines.append(
            f"{risk:<10}: {count}"
        )
    # ==================================================
    # Recommendations
    # ==================================================

    lines.append("")
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 70)

    if brute_force_alerts:
        lines.append(
            "- Investigate brute force activity and "
            "review authentication logs."
        )

        if any(
            alert.get("successful_login")
            for alert in brute_force_alerts
        ):
            lines.append(
                "- Verify accounts affected by successful "
                "logins following failed authentication attempts."
            )

    if port_scan_alerts:
        lines.append(
            "- Investigate port scanning sources and "
            "review exposed services on targeted hosts."
        )

    if dns_alerts:
        lines.append(
            "- Investigate suspicious DNS queries and "
            "review endpoints generating abnormal DNS traffic."
        )

    if beacon_alerts:
        lines.append(
            "- Investigate periodic network connections and "
            "validate the destination for possible C2 activity."
        )

    if threat_alerts:
        lines.append(
            "- Investigate communication with known malicious "
            "IPs and review affected hosts."
        )

    if total_alerts == 0:
        lines.append(
            "- No security alerts require immediate action."
        )
    lines.append("")
    lines.append("=" * 70)
    lines.append("End of Report")
    lines.append("=" * 70)

    return "\n".join(lines)


# ==================================================
# Save Report
# ==================================================

def save_report(
    report,
    output_path
):
    """
    Save a generated report to disk.
    """

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path.write_text(
        report,
        encoding="utf-8"
    )
