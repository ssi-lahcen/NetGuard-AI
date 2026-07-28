"""
==================================================
NetGuard-AI
Configuration
==================================================

Central configuration for the entire project.

Author:
    Lahcen Elkadi
"""

from pathlib import Path

# ==================================================
# Project Directories
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

LOGS_DIR = BASE_DIR / "logs"

REPORTS_DIR = BASE_DIR / "reports"

DATASETS_DIR = BASE_DIR / "datasets"

DATA_DIR = BASE_DIR / "data"

# ==================================================
# Log Files
# ==================================================

NETWORK_LOG_FILE = LOGS_DIR / "network_logs.csv"

AUTH_LOG_FILE = LOGS_DIR / "auth_logs.csv"

# Backward compatibility
LOG_FILE = NETWORK_LOG_FILE

# ==================================================
# Port Scan Detection
# ==================================================

PORT_SCAN_THRESHOLD = 5

TIME_WINDOW_SECONDS = 60

LOW_RISK_PORTS = 5

MEDIUM_RISK_PORTS = 10

HIGH_RISK_PORTS = 20

# ==================================================
# Brute Force Detection
# ==================================================

BRUTE_FORCE_THRESHOLD = 5

BRUTE_FORCE_TIME_WINDOW = 60

HIGH_ATTEMPTS = 10

CRITICAL_ATTEMPTS = 20

# ==================================================
# DNS Tunneling Detection
# ==================================================

DNS_QUERY_LENGTH_THRESHOLD = 50

DNS_REQUEST_THRESHOLD = 5
