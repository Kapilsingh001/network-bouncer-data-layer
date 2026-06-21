"""Tests for src.scoring.enricher (Dev 2 -> Dev 3 integration)."""

from __future__ import annotations

import pandas as pd
import pytest

from src.detection.detector import detect_scanning
from src.scoring.enricher import ENRICHED_COLUMNS, enrich_detections


@pytest.fixture
def population_flows() -> pd.DataFrame:
    """20 quiet hosts + 2 blatant scanners (enough hosts for a stat baseline)."""
    rows = []
    for h in range(20):
        ip = f"10.1.0.{h}"
        for c in range(8):
            rows.append((ip, "10.2.0.5", 30000 + c, 443, "tcp", "https", "FIN"))
    # Horizontal scanner.
    for d in range(40):
        rows.append(("10.9.9.1", f"172.16.0.{d}", 40000 + d, 80, "tcp", "-", "INT"))
    # Vertical scanner.
    for p in range(40):
        rows.append(("10.9.9.2", "172.16.5.5", 50000 + p, 1000 + p, "tcp", "-", "REQ"))
    return pd.DataFrame(
        rows,
        columns=["srcip", "dstip", "sport", "dsport", "proto", "service", "state"],
    )


def test_enriched_schema(population_flows):
    result = detect_scanning(population_flows)
    enriched = enrich_detections(result)
    for col in ENRICHED_COLUMNS:
        assert col in enriched.columns


def test_scanner_is_high_severity(population_flows):
    enriched = enrich_detections(detect_scanning(population_flows)).set_index("srcip")
    for scanner in ("10.9.9.1", "10.9.9.2"):
        assert enriched.loc[scanner, "severity_level"] in ("High", "Critical")
        assert enriched.loc[scanner, "severity_score"] > 0


def test_quiet_host_is_low_or_none(population_flows):
    enriched = enrich_detections(detect_scanning(population_flows)).set_index("srcip")
    assert enriched.loc["10.1.0.0", "severity_level"] in ("None", "Low")


def test_sorted_by_severity_desc(population_flows):
    enriched = enrich_detections(detect_scanning(population_flows))
    scores = enriched["severity_score"].tolist()
    assert scores == sorted(scores, reverse=True)


def test_scanner_has_explanation(population_flows):
    enriched = enrich_detections(detect_scanning(population_flows)).set_index("srcip")
    expl = enriched.loc["10.9.9.1", "severity_explanation"]
    assert isinstance(expl, list) and len(expl) > 0


def test_empty_input():
    enriched = enrich_detections(pd.DataFrame())
    assert enriched.empty
    assert "severity_level" in enriched.columns


def test_missing_srcip_raises():
    with pytest.raises(ValueError):
        enrich_detections(pd.DataFrame({"foo": [1, 2]}))
