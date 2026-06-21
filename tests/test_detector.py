"""Tests for src.detection.detector (end-to-end detection)."""

from __future__ import annotations

import pandas as pd
import pytest

from src.detection.config import DetectionConfig
from src.detection.detector import RuleBasedDetector, detect_scanning
from src.detection.rules import RuleResult


@pytest.fixture
def flows() -> pd.DataFrame:
    """One obvious block scanner plus one clearly benign host."""
    rows = []
    # Block scanner: 30 hosts x ~30 ports, no service, incomplete states.
    for d in range(30):
        for p in range(30):
            rows.append(("10.0.0.1", f"172.16.0.{d}", 40000 + p, 1000 + p, "tcp", None, "INT"))
    # Benign: a web server's worth of repeated, completed HTTPS connections.
    for i in range(60):
        rows.append(("10.0.0.50", "172.16.5.5", 30000 + i, 443, "tcp", "https", "FIN"))
    return pd.DataFrame(
        rows,
        columns=["srcip", "dstip", "sport", "dsport", "proto", "service", "state"],
    )


def test_flags_scanner_not_benign(flows):
    result = detect_scanning(flows).set_index("srcip")
    assert bool(result.loc["10.0.0.1", "is_suspicious"]) is True
    assert bool(result.loc["10.0.0.50", "is_suspicious"]) is False


def test_classification_labels(flows):
    result = detect_scanning(flows).set_index("srcip")
    assert result.loc["10.0.0.1", "classification"] == "Suspicious (Backdoor/Analysis)"
    assert result.loc["10.0.0.50", "classification"] == "Normal"


def test_severity_tiers(flows):
    result = detect_scanning(flows).set_index("srcip")
    # The block scanner trips several high-weight rules -> High severity.
    assert result.loc["10.0.0.1", "severity"] == "High"
    # The benign host has no severity tier.
    assert result.loc["10.0.0.50", "severity"] == "None"


def test_scanner_has_reasons_and_categories(flows):
    result = detect_scanning(flows).set_index("srcip")
    scanner = result.loc["10.0.0.1"]
    assert scanner["rule_hits"] >= 2
    assert "block" in scanner["scan_categories"]
    assert len(scanner["reasons"]) == scanner["rule_hits"]
    assert scanner["suspicion_score"] > 0


def test_alerts_only_contains_suspicious(flows):
    detector = RuleBasedDetector()
    result = detector.detect_from_flows(flows)
    alerts = detector.alerts(result)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["srcip"] == "10.0.0.1"
    assert "evidence" in alert
    assert alert["evidence"]["unique_destinations"] == 30


def test_result_sorted_suspicious_first(flows):
    result = detect_scanning(flows)
    # The most suspicious host must be the first row.
    assert result.iloc[0]["srcip"] == "10.0.0.1"


def test_empty_input():
    result = detect_scanning(pd.DataFrame())
    assert result.empty
    assert "is_suspicious" in result.columns


def test_config_sensitivity_controls_flagging(flows):
    # With an unreachably high volume floor, nothing should be flagged.
    strict = DetectionConfig(min_connections=10_000_000)
    result = detect_scanning(flows, config=strict)
    assert result["is_suspicious"].sum() == 0


def test_min_rules_to_flag_raises_bar(flows):
    # Require 99 concurrent rules -> even the scanner cannot satisfy that.
    cfg = DetectionConfig(min_rules_to_flag=99)
    result = detect_scanning(flows, config=cfg)
    assert result["is_suspicious"].sum() == 0


def test_custom_rule_set():
    # A detector with no rules flags nobody.
    detector = RuleBasedDetector(rules=[])
    row = pd.Series({"srcip": "x"})
    verdict = detector.evaluate_host(row)
    assert verdict.is_suspicious is False
    assert verdict.rule_hits == 0
