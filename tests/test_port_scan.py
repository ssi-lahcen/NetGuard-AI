"""
Tests for port_scan.py
"""

from config import LOG_FILE

from modules.parser import parse_logs

from modules.port_scan import (
    detect_port_scans,
)


def test_port_scan():

    dataframe = parse_logs(LOG_FILE)

    alerts = detect_port_scans(
        dataframe
    )

    assert isinstance(alerts, list)
