"""
Project configuration.
All configurable values are stored here.

"""

from pathlib import Path

# Project root directory
BASE_DIR = Path(__file__).resolve().parent

# Logs
LOG_FILE = BASE_DIR / "logs" / "network_logs.csv"

# Reports
REPORTS_DIR = BASE_DIR / "reports"

# Datasets
DATASETS_DIR = BASE_DIR / "datasets"

# Data
DATA_DIR = BASE_DIR / "data"

# ===========================
# Port Scan Detection
# ===========================

PORT_SCAN_THRESHOLD = 5

TIME_WINDOW_SECONDS = 60

LOW_RISK_PORTS = 5
MEDIUM_RISK_PORTS = 10
HIGH_RISK_PORTS = 20
