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

    print(dataframe)


if __name__ == "__main__":
    main()

