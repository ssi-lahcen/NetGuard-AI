"""
NetGuard-AI
Main Entry Point
"""

from config import LOG_FILE
from modules.parser import parse_logs


def main():
    """
    Program entry point.
    """

    print("=" * 50)
    print("NetGuard-AI")
    print("=" * 50)

    dataframe = parse_logs(LOG_FILE)

    print("\nLogs loaded successfully.\n")

    print(f"Total Log Entries : {len(dataframe)}")
    print(f"Columns           : {len(dataframe.columns)}")
    print(f"Source IPs        : {dataframe['src_ip'].nunique()}")
    print(f"Destination IPs   : {dataframe['dst_ip'].nunique()}")
    print(f"Protocols         : {', '.join(dataframe['protocol'].unique())}")


if __name__ == "__main__":
    main()

