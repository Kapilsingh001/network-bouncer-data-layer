"""Statistical anomaly detection + severity classification layer (Dev 3).

Enhances — does not replace — the Dev 2 rule-based detector. It analyses the
per-host feature matrix as a *population*, finds hosts that are statistical
outliers (mean / standard deviation / z-score), and fuses that signal with the
rule-based evidence into an explainable severity classification
(None / Low / Medium / High / Critical).
"""

from __future__ import annotations

from src.scoring.anomaly import (
    ANOMALY_COLUMNS,
    AnomalyResult,
    StatisticalAnomalyDetector,
    detect_anomalies,
)
from src.scoring.config import ScoringConfig
from src.scoring.enricher import ENRICHED_COLUMNS, enrich_detections
from src.scoring.severity import (
    SEVERITY_COLUMNS,
    SeverityClassifier,
    SeverityResult,
)

__all__ = [
    "ScoringConfig",
    "StatisticalAnomalyDetector",
    "AnomalyResult",
    "detect_anomalies",
    "ANOMALY_COLUMNS",
    "SeverityClassifier",
    "SeverityResult",
    "SEVERITY_COLUMNS",
    "enrich_detections",
    "ENRICHED_COLUMNS",
]
