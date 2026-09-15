"""
Tests for NetGuard-AI security detectors.
"""

import pandas as pd

from modules.brute_force import detect_brute_force
from modules.dns_tunneling import detect_dns_tunneling
from modules.beaconing import detect_beaconing
from modules.threat_intel import detect_malicious_ips


def test_brute_force_detection():

    dataframe = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-09-15 10:00:00",
            "2026-09-15 10:00:01",
            "2026-09-15 10:00:02",
            "2026-09-15 10:00:03",
            "2026-09-15 10:00:04",
        ]),
        "src_ip": [
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
        ],
        "dst_ip": [
            "10.0.0.20",
            "10.0.0.20",
            "10.0.0.20",
            "10.0.0.20",
            "10.0.0.20",
        ],
        "service": [
            "SSH",
            "SSH",
            "SSH",
            "SSH",
            "SSH",
        ],
        "status": [
            "FAILED",
            "FAILED",
            "FAILED",
            "FAILED",
            "FAILED",
        ],
        "username": [
            "admin",
            "admin",
            "admin",
            "admin",
            "admin",
        ],
    })

    alerts = detect_brute_force(dataframe)

    assert len(alerts) > 0
    assert alerts[0]["source_ip"] == "192.168.1.50"


def test_dns_tunneling_detection():

    dataframe = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-09-15 10:00:00",
            "2026-09-15 10:00:01",
            "2026-09-15 10:00:02",
            "2026-09-15 10:00:03",
            "2026-09-15 10:00:04",
            "2026-09-15 10:00:05",
        ]),
        "src_ip": [
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
        ],
        "dst_ip": [
            "8.8.8.8",
            "8.8.8.8",
            "8.8.8.8",
            "8.8.8.8",
            "8.8.8.8",
            "8.8.8.8",
        ],
        "query": [
            "aHR0cHM6Ly9leGFtcGxlLTAwMS5ldmlsLmNvbQ==.evil.com",
            "aHR0cHM6Ly9leGFtcGxlLTAwMi5ldmlsLmNvbQ==.evil.com",
            "aHR0cHM6Ly9leGFtcGxlLTAwMy5ldmlsLmNvbQ==.evil.com",
            "aHR0cHM6Ly9leGFtcGxlLTAwNC5ldmlsLmNvbQ==.evil.com",
            "aHR0cHM6Ly9leGFtcGxlLTAwNS5ldmlsLmNvbQ==.evil.com",
            "aHR0cHM6Ly9leGFtcGxlLTAwNi5ldmlsLmNvbQ==.evil.com",
        ],
        "record_type": [
            "A",
            "A",
            "A",
            "A",
            "A",
            "A",
        ],
        "response_size": [
            120,
            120,
            120,
            120,
            120,
            120,
        ],
    })

    alerts = detect_dns_tunneling(dataframe)

    assert len(alerts) > 0
    assert alerts[0]["source_ip"] == "192.168.1.50"


def test_beaconing_detection():

    dataframe = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-09-15 10:00:00",
            "2026-09-15 10:01:00",
            "2026-09-15 10:02:00",
            "2026-09-15 10:03:00",
            "2026-09-15 10:04:00",
        ]),
        "src_ip": [
            "192.168.1.99",
            "192.168.1.99",
            "192.168.1.99",
            "192.168.1.99",
            "192.168.1.99",
        ],
        "dst_ip": [
            "45.77.12.99",
            "45.77.12.99",
            "45.77.12.99",
            "45.77.12.99",
            "45.77.12.99",
        ],
        "protocol": [
            "HTTPS",
            "HTTPS",
            "HTTPS",
            "HTTPS",
            "HTTPS",
        ],
        "bytes": [
            515,
            518,
            512,
            520,
            516,
        ],
    })

    alerts = detect_beaconing(dataframe)

    assert len(alerts) > 0
    assert alerts[0]["source_ip"] == "192.168.1.99"
    assert alerts[0]["risk"] == "MEDIUM"


def test_threat_intelligence_detection():

    dataframe = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-09-15 10:00:00",
        ]),
        "src_ip": [
            "192.168.1.25",
        ],
        "dst_ip": [
            "45.77.12.8",
        ],
        "dst_port": [
            443,
        ],
        "protocol": [
            "TCP",
        ],
        "bytes": [
            500,
        ],
    })

    alerts = detect_malicious_ips(dataframe)

    assert len(alerts) > 0
    assert alerts[0]["matched_ip"] == "45.77.12.8"
