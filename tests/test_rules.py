"""Tests for src.detection.rules (each rule in isolation)."""

from __future__ import annotations

import pandas as pd
import pytest

from src.detection.config import DetectionConfig
from src.detection.rules import DEFAULT_RULES

CONFIG = DetectionConfig()
RULES = {rule.name: rule for rule in DEFAULT_RULES}


def _row(**overrides) -> pd.Series:
    """A neutral feature row; override only the fields a test cares about."""
    base = {
        "srcip": "10.0.0.1",
        "total_connections": 100,
        "unique_destinations": 1,
        "unique_dst_ports": 1,
        "unique_src_ports": 1,
        "unique_protocols": 1,
        "unique_services": 1,
        "ports_per_destination": 1.0,
        "conn_per_destination": 100.0,
        "dst_port_ratio": 0.01,
        "dst_ratio": 0.01,
        "null_service_ratio": 0.0,
        "incomplete_ratio": 0.0,
    }
    base.update(overrides)
    return pd.Series(base)


def test_horizontal_scan_fires():
    row = _row(unique_destinations=50, conn_per_destination=2.0)
    assert RULES["horizontal_scan"].evaluate(row, CONFIG).triggered


def test_vertical_scan_fires():
    row = _row(unique_dst_ports=40, unique_destinations=2)
    assert RULES["vertical_scan"].evaluate(row, CONFIG).triggered


def test_vertical_scan_does_not_fire_when_many_destinations():
    # Many ports but spread over many hosts -> that's a block scan, not vertical.
    row = _row(unique_dst_ports=40, unique_destinations=50)
    assert not RULES["vertical_scan"].evaluate(row, CONFIG).triggered


def test_block_scan_fires():
    row = _row(unique_destinations=30, unique_dst_ports=30)
    assert RULES["block_scan"].evaluate(row, CONFIG).triggered


def test_high_port_diversity_fires():
    row = _row(dst_port_ratio=0.95)
    assert RULES["high_port_diversity"].evaluate(row, CONFIG).triggered


def test_low_connection_reuse_fires():
    row = _row(unique_destinations=40, conn_per_destination=1.0)
    assert RULES["low_connection_reuse"].evaluate(row, CONFIG).triggered


def test_unknown_service_probing_fires():
    row = _row(null_service_ratio=0.8)
    assert RULES["unknown_service_probing"].evaluate(row, CONFIG).triggered


def test_incomplete_connections_fires():
    row = _row(incomplete_ratio=0.9)
    assert RULES["incomplete_connections"].evaluate(row, CONFIG).triggered


def test_volume_gate_blocks_low_volume_hosts():
    # Strong ratios but only 3 connections -> no scan rule should fire.
    row = _row(
        total_connections=3,
        unique_destinations=50,
        unique_dst_ports=50,
        dst_port_ratio=1.0,
    )
    fired = [r.name for r in DEFAULT_RULES if r.evaluate(row, CONFIG).triggered]
    assert fired == []


def test_indicator_text_present_when_fired():
    row = _row(unique_destinations=50)
    result = RULES["horizontal_scan"].evaluate(row, CONFIG)
    assert result.triggered
    assert "distinct destinations" in result.indicator
    assert result.weight == pytest.approx(2.0)
