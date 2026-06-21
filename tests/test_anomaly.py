"""Tests for src.scoring.anomaly (statistical outlier detection)."""

from __future__ import annotations

import pandas as pd
import pytest

from src.scoring.anomaly import (
    ANOMALY_COLUMNS,
    StatisticalAnomalyDetector,
    detect_anomalies,
)
from src.scoring.config import ScoringConfig


def _matrix_with_outlier(n_normal: int = 24) -> pd.DataFrame:
    """A population of quiet hosts plus one extreme outlier.

    ``n_normal`` is large enough that a single extreme host can exceed a
    z-score of 3 (max achievable z for one outlier is ~sqrt(n_normal)).
    """
    base = dict(
        total_connections=10, unique_destinations=2, unique_dst_ports=2,
        unique_src_ports=5, unique_protocols=1, unique_services=1,
        ports_per_destination=1.0, dst_port_ratio=0.2, dst_ratio=0.2,
        null_service_ratio=0.0, incomplete_ratio=0.0,
    )
    rows = [dict(srcip=f"10.0.0.{i}", **base) for i in range(n_normal)]
    rows.append(dict(
        srcip="10.0.0.250",
        total_connections=5000, unique_destinations=900, unique_dst_ports=900,
        unique_src_ports=900, unique_protocols=6, unique_services=12,
        ports_per_destination=80.0, dst_port_ratio=1.0, dst_ratio=1.0,
        null_service_ratio=1.0, incomplete_ratio=1.0,
    ))
    return pd.DataFrame(rows)


def test_detects_extreme_outlier():
    matrix = _matrix_with_outlier()
    result = detect_anomalies(matrix).set_index("srcip")
    outlier = result.loc["10.0.0.250"]
    assert outlier["n_anomaly_indicators"] >= 3
    assert outlier["max_zscore"] >= 3.0
    assert outlier["outlier_score"] > 0
    assert len(outlier["anomaly_indicators"]) == outlier["n_anomaly_indicators"]


def test_quiet_hosts_are_not_flagged():
    matrix = _matrix_with_outlier()
    result = detect_anomalies(matrix).set_index("srcip")
    quiet = result.loc["10.0.0.0"]
    assert quiet["n_anomaly_indicators"] == 0
    assert quiet["outlier_score"] == 0.0


def test_output_schema():
    result = detect_anomalies(_matrix_with_outlier())
    for col in ANOMALY_COLUMNS:
        assert col in result.columns


def test_small_population_is_skipped():
    # Fewer hosts than min_population -> neutral results, no spurious z-scores.
    matrix = _matrix_with_outlier(n_normal=2)  # 3 hosts total
    result = detect_anomalies(matrix)
    assert (result["n_anomaly_indicators"] == 0).all()
    assert (result["outlier_score"] == 0.0).all()


def test_zero_variance_feature_no_outlier():
    # All hosts identical -> std 0 -> z 0 -> nobody flagged.
    rows = [
        dict(srcip=f"h{i}", total_connections=10, unique_destinations=2,
             unique_dst_ports=2, unique_src_ports=2, unique_protocols=1,
             unique_services=1, ports_per_destination=1.0, dst_port_ratio=0.5,
             dst_ratio=0.5, null_service_ratio=0.0, incomplete_ratio=0.0)
        for i in range(10)
    ]
    result = detect_anomalies(pd.DataFrame(rows))
    assert (result["n_anomaly_indicators"] == 0).all()


def test_empty_input():
    result = detect_anomalies(pd.DataFrame())
    assert result.empty
    assert "outlier_score" in result.columns


def test_transform_before_fit_raises():
    det = StatisticalAnomalyDetector()
    with pytest.raises(RuntimeError):
        det.transform(_matrix_with_outlier())


def test_custom_z_threshold_changes_sensitivity():
    matrix = _matrix_with_outlier()
    strict = detect_anomalies(matrix, ScoringConfig(z_threshold=10.0)).set_index("srcip")
    loose = detect_anomalies(matrix, ScoringConfig(z_threshold=2.0)).set_index("srcip")
    # A higher threshold should flag no more indicators than a lower one.
    assert strict.loc["10.0.0.250", "n_anomaly_indicators"] <= \
        loose.loc["10.0.0.250", "n_anomaly_indicators"]
