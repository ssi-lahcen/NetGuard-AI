"""NetGuard-AI command-line entry point."""

from __future__ import annotations

import argparse
import sys

from config import LOG_FILE, TOP_LIMIT
from modules.parser import LogValidationError, parse_logs_with_report
from modules.statistics import build_network_profile


def positive_int(value: str) -> int:
    """Argparse converter for positive integers."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze network CSV logs")
    parser.add_argument("log_file", nargs="?", type=str, default=str(LOG_FILE), help="CSV log file")
    parser.add_argument("--top", type=positive_int, default=TOP_LIMIT, help="Number of top entries to display")
    return parser


def format_bytes(value: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def print_profile(profile: dict) -> None:
    print("NETGUARD-AI NETWORK PROFILE")
    print("=" * 50)

    basic = profile["basic_statistics"]
    print("\nNETWORK STATISTICS")
    print("-" * 50)
    print(f"Total Events       : {basic['total_events']}")
    print(f"Unique Source IPs  : {basic['unique_source_ips']}")
    print(f"Unique Destination IPs: {basic['unique_destination_ips']}")
    print(f"Unique Ports       : {basic['unique_ports']}")
    print(f"Unique Protocols   : {basic['unique_protocols']}")
    print(f"Total Bytes        : {format_bytes(basic['total_bytes'])}")

    print("\nTOP TALKERS")
    print("-" * 50)
    for ip_address, event_count in profile["top_talkers"].items():
        print(f"{ip_address:<20}{event_count} events")

    print("\nTOP DESTINATION PORTS")
    print("-" * 50)
    for port, event_count in profile["top_ports"].items():
        print(f"Port {port:<15}{event_count} events")

    print("\nPROTOCOL DISTRIBUTION")
    print("-" * 50)
    for protocol, event_count in profile["protocol_distribution"].items():
        print(f"{protocol:<20}{event_count} events")

    print("\nACTION DISTRIBUTION")
    print("-" * 50)
    for action, event_count in profile["action_distribution"].items():
        print(f"{action:<20}{event_count} events")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        dataframe, report = parse_logs_with_report(args.log_file)
    except (FileNotFoundError, LogValidationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(f"Loaded {report['valid_rows']} valid rows ({report['removed_rows']} removed).")
    print_profile(build_network_profile(dataframe, args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
