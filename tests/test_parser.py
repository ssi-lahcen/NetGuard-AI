"""
Tests for parser.py
"""

from modules.parser import parse_logs

from config import LOG_FILE


def test_parse_logs():

    dataframe = parse_logs(LOG_FILE)

    assert len(dataframe) > 0
