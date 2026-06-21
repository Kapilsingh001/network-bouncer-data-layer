"""Tests for src.features.feature_builder."""

from __future__ import annotations

import pandas as pd
import pytest

from src.features.feature_builder import (
    FEATURE_MATRIX_COLUMNS,
    build_host_feature_matrix,
)


@pytest.fixture
def mixed_flows() -> pd.DataFrame:
    """A horizontal scanner, a vertical scanner, and a benign host."""
    rows = []
    # Horizontal scanner: 1 source -> 40 destinations, same port, one flow each.
    for i in range(40):
        rows.append(("10.0.0.1", f"192.168.1.{i}", 40000 + i, 80, "tcp", None, "INT"))
    # Vertical scanner: 1 source -> 1 destination, 30 distinct ports.
    for p in range(30):
        rows.append(("10.0.0.2", "192.168.5.5", 50000 + p, 1000 + p, "tcp", None, "REQ"))
    # Benign host: a few repeated connections to one server on one service.
    for i in range(8):
        rows.append(("10.0.0.3", "192.168.9.9", 33000 + i, 443, "tcp", "https", "FIN"))
    return pd.DataFrame(
        rows,
        columns=["srcip", "dstip", "sport", "dsport", "proto", "service", "state"],
    )


def test_matrix_schema_and_one_row_per_host(mixed_flows):
    matrix = build_host_feature_matrix(mixed_flows)
    assert list(matrix.columns) == FEATURE_MATRIX_COLUMNS
    assert set(matrix["srcip"]) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_horizontal_scanner_features(mixed_flows):
    matrix = build_host_feature_matrix(mixed_flows).set_index("srcip")
    h = matrix.loc["10.0.0.1"]
    assert h["total_connections"] == 40
    assert h["unique_destinations"] == 40
    assert h["unique_dst_ports"] == 1          # always port 80
    assert h["conn_per_destination"] == pytest.approx(1.0)  # each dest hit once
    assert h["dst_ratio"] == pytest.approx(1.0)            # every flow a new dest


def test_vertical_scanner_features(mixed_flows):
    matrix = build_host_feature_matrix(mixed_flows).set_index("srcip")
    v = matrix.loc["10.0.0.2"]
    assert v["unique_destinations"] == 1
    assert v["unique_dst_ports"] == 30
    # 30 ports concentrated on a single host -> very high vertical intensity.
    assert v["ports_per_destination"] == pytest.approx(30.0)


def test_null_service_ratio(mixed_flows):
    matrix = build_host_feature_matrix(mixed_flows).set_index("srcip")
    # Scanners had service=None for every flow; benign host had a service.
    assert matrix.loc["10.0.0.1", "null_service_ratio"] == pytest.approx(1.0)
    assert matrix.loc["10.0.0.3", "null_service_ratio"] == pytest.approx(0.0)


def test_incomplete_ratio_uses_state(mixed_flows):
    matrix = build_host_feature_matrix(mixed_flows).set_index("srcip")
    # INT/REQ are not established; FIN is.
    assert matrix.loc["10.0.0.1", "incomplete_ratio"] == pytest.approx(1.0)
    assert matrix.loc["10.0.0.3", "incomplete_ratio"] == pytest.approx(0.0)


def test_empty_input_returns_schema():
    matrix = build_host_feature_matrix(pd.DataFrame())
    assert matrix.empty
    assert list(matrix.columns) == FEATURE_MATRIX_COLUMNS


def test_missing_optional_columns_are_safe():
    df = pd.DataFrame({"srcip": ["a", "a"], "dstip": ["x", "y"]})
    matrix = build_host_feature_matrix(df).set_index("srcip")
    # No port/proto/service/state columns -> ratios default to 0, no crash.
    assert matrix.loc["a", "total_connections"] == 2
    assert matrix.loc["a", "unique_destinations"] == 2
    assert matrix.loc["a", "null_service_ratio"] == 0.0
    assert matrix.loc["a", "incomplete_ratio"] == 0.0
