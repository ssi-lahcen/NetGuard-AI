import pandas as pd
import pytest

from modules.parser import LogValidationError, parse_logs, validate_columns


COLUMNS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes"]


def test_parse_valid_and_duplicate_rows(tmp_path):
    path = tmp_path / "logs.csv"
    pd.DataFrame([
        ["2026-01-01 10:00:00", "192.168.1.1", "10.0.0.1", 80, "tcp", "allow", 100],
        ["2026-01-01 10:00:00", "192.168.1.1", "10.0.0.1", 80, "tcp", "allow", 100],
    ], columns=COLUMNS).to_csv(path, index=False)

    dataframe = parse_logs(path)

    assert len(dataframe) == 1
    assert str(dataframe.loc[0, "protocol"]) == "TCP"
    assert str(dataframe.loc[0, "action"]) == "ALLOW"


def test_parse_removes_invalid_network_rows(tmp_path):
    path = tmp_path / "logs.csv"
    pd.DataFrame([
        ["2026-01-01 10:00:00", "not-an-ip", "10.0.0.1", 80, "TCP", "ALLOW", 100],
        ["2026-01-01 10:00:00", "192.168.1.1", "10.0.0.1", 70000, "TCP", "ALLOW", 100],
        ["2026-01-01 10:00:00", "192.168.1.1", "10.0.0.1", 443, "TCP", "DENY", -1],
        ["2026-01-01 10:00:00", "192.168.1.1", "10.0.0.1", 443, "TCP", "ALLOW", 100],
    ], columns=COLUMNS).to_csv(path, index=False)

    dataframe = parse_logs(path)

    assert len(dataframe) == 1
    assert dataframe.loc[0, "dst_port"] == 443


def test_missing_columns_raise_validation_error():
    with pytest.raises(LogValidationError, match="Missing required columns"):
        validate_columns(pd.DataFrame({"timestamp": []}))
