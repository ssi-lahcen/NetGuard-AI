"""
Project configuration.
All configurable values are stored here.
"""

from pathlib import Path
import os


PROJECT_ROOT = Path(__file__).resolve().parent
LOG_FILE = Path(os.environ.get("NETGUARD_LOG_FILE", PROJECT_ROOT / "logs" / "network_logs.csv"))
TOP_LIMIT = 5
MAX_CSV_BYTES = 100 * 1024 * 1024
