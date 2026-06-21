"""Tests for src.scoring.severity (fused severity classification)."""

from __future__ import annotations

import pandas as pd
import pytest

from src.scoring.config import ScoringConfig
from src.scoring.severity import SeverityClassifier

CLF = SeverityClassifier()


def _row(**overrides) -> pd.Series:
    base = {
        "srcip": "10.0.0.1",
        "is_suspicious": False,
        "suspicion_score": 0.0,
        "rule_hits": 0,
        "triggered_rules": [],
        "n_anomaly_indicators": 0,
        "max_zscore": 0.0,
        "anomaly_indicators": [],
    }
    base.update(overrides)
    return pd.Series(base)


def test_clean_host_is_none():
    result = CLF.classify_row(_row())
    assert result.severity_level == "None"
    assert result.severity_score == 0.0


def test_single_rule_gets_meaningful_tier():
    # A single high_port_diversity hit (weight 1.5) -> 1.5*18 = 27 pts -> Medium,
    # not a trivial "Low". This is the calibration the reviewer flagged.
    result = CLF.classify_row(_row(is_suspicious=True, suspicion_score=1.5, rule_hits=1,
                                   triggered_rules=["high_port_diversity"]))
    assert result.severity_level == "Medium"
    assert result.severity_score >= 25
    assert any("Rule-based detection" in r for r in result.severity_explanation)


def test_block_scan_is_high():
    # A block scan alone (weight 3.0) -> 3.0*18 = 54 pts -> High (was "Low" before).
    result = CLF.classify_row(_row(is_suspicious=True, suspicion_score=3.0, rule_hits=1,
                                   triggered_rules=["block_scan"]))
    assert result.severity_level == "High"


def test_corroborated_escalates_to_critical():
    # Rule-flagged AND >= 3 statistical anomalies -> Critical escalation.
    result = CLF.classify_row(_row(
        is_suspicious=True, suspicion_score=4.0, rule_hits=3,
        triggered_rules=["block_scan", "horizontal_scan"],
        n_anomaly_indicators=4, max_zscore=6.0,
        anomaly_indicators=["a", "b", "c", "d"],
    ))
    assert result.severity_level == "Critical"
    assert any("Corroborated" in r for r in result.severity_explanation)
    assert any("Multiple statistical anomaly" in r for r in result.severity_explanation)


def test_high_score_without_escalation():
    # High rule score, no stats -> High by score alone.
    result = CLF.classify_row(_row(is_suspicious=True, suspicion_score=10.0, rule_hits=5,
                                   triggered_rules=["block_scan"]))
    assert result.severity_level == "High"


def test_statistical_only_host():
    # Not rule-flagged but a statistical outlier -> still gets a (low) severity.
    result = CLF.classify_row(_row(n_anomaly_indicators=1, max_zscore=4.0,
                                   anomaly_indicators=["unique_dst_ports = 900 (4.0sigma above mean 2.00)"]))
    assert result.severity_level in ("Low", "Medium")
    assert result.severity_score > 0
    assert any("Statistical outlier" in r for r in result.severity_explanation)


def test_classify_dataframe_schema():
    df = pd.DataFrame([_row(), _row(is_suspicious=True, suspicion_score=5.0, rule_hits=2)])
    out = CLF.classify(df)
    assert list(out.columns) == ["srcip", "severity_score", "severity_level", "severity_explanation"]
    assert len(out) == 2


def test_thresholds_are_configurable():
    cfg = ScoringConfig(medium_threshold=10, high_threshold=20, critical_threshold=30)
    clf = SeverityClassifier(cfg)
    # suspicion 1.5 -> 27 points -> High (>=20, <30) under this stricter policy.
    result = clf.classify_row(_row(is_suspicious=True, suspicion_score=1.5, rule_hits=1))
    assert result.severity_level == "High"


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        ScoringConfig(medium_threshold=80, high_threshold=50, critical_threshold=30)
