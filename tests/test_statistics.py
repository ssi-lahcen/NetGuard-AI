"""
Tests for statistics.py
"""

from config import LOG_FILE

from modules.parser import parse_logs

from modules.statistics import (
    build_network_profile,
)


def test_statistics():

    dataframe = parse_logs(LOG_FILE)

    profile = build_network_profile(
        dataframe
    )

    assert profile["basic_statistics"]["total_events"] > 0

    assert profile["basic_statistics"]["unique_source_ips"] > 0

    assert profile["basic_statistics"]["unique_ports"] > 0
