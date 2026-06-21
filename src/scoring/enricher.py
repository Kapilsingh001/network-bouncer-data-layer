"""Enrichment orchestrator for the Network Bouncer scoring layer (Dev 3).

The single integration point with Dev 2. Takes the Dev 2 detection result
(host feature matrix + rule verdicts) and enriches every host with:

* statistical anomaly indicators + outlier score (Dev 3 anomaly module),
* a fused, explainable severity score + level (Dev 3 severity module).

Input  : output of ``RuleBasedDetector.detect()`` / ``detect_scanning()``.
Output : the same table with :data:`ENRICHED_COLUMNS` appended, sorted by
         severity score (most severe first).
"""

from __future__ import annotations

import pandas as pd

from src.scoring.anomaly import ANOMALY_COLUMNS, StatisticalAnomalyDetector
from src.scoring.config import ScoringConfig
from src.scoring.severity import SEVERITY_COLUMNS, SeverityClassifier
from src.utils.logger import get_logger

logger = get_logger(__name__)

# All columns Dev 3 adds to the Dev 2 result.
ENRICHED_COLUMNS = [*ANOMALY_COLUMNS, *SEVERITY_COLUMNS]


def enrich_detections(
    detection_result: pd.DataFrame,
    config: ScoringConfig | None = None,
) -> pd.DataFrame:
    """Enrich Dev 2 detection output with anomaly + severity intelligence.

    Parameters
    ----------
    detection_result:
        DataFrame from Dev 2 (one row per host: feature columns + rule verdicts).
    config:
        Scoring policy. Defaults to :class:`ScoringConfig`.

    Returns
    -------
    pandas.DataFrame
        ``detection_result`` with :data:`ENRICHED_COLUMNS` added, sorted by
        ``severity_score`` (descending).
    """
    config = config or ScoringConfig()

    if detection_result is None or detection_result.empty:
        logger.warning("enrich_detections received an empty detection result")
        cols = list(detection_result.columns) if detection_result is not None else []
        return pd.DataFrame(columns=cols + ENRICHED_COLUMNS)

    if "srcip" not in detection_result.columns:
        raise ValueError("detection_result must contain a 'srcip' column.")

    # 1. Statistical anomaly detection over the host population.
    anomaly_detector = StatisticalAnomalyDetector(config=config)
    anomalies = anomaly_detector.fit(detection_result).transform(detection_result)

    enriched = detection_result.merge(anomalies, on="srcip", how="left")
    enriched = _fill_missing_anomaly_columns(enriched)

    # 2. Fused severity classification (rules + statistics).
    classifier = SeverityClassifier(config=config)
    severity = classifier.classify(enriched)
    enriched = enriched.merge(severity, on="srcip", how="left")

    enriched = enriched.sort_values(
        "severity_score", ascending=False, ignore_index=True
    )
    n_critical = int((enriched["severity_level"] == "Critical").sum())
    n_high = int((enriched["severity_level"] == "High").sum())
    logger.info(
        "Enrichment complete: %d Critical, %d High of %d host(s)",
        n_critical, n_high, len(enriched),
    )
    return enriched


def _fill_missing_anomaly_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Guarantee anomaly columns exist with safe defaults after the merge."""
    defaults = {
        "outlier_score": 0.0,
        "max_zscore": 0.0,
        "n_anomaly_indicators": 0,
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default
        else:
            df[col] = df[col].fillna(default)

    # List/dict columns: fill NaNs (from a left-merge miss) with empty containers.
    for col, empty in (("anomaly_indicators", list), ("feature_zscores", dict)):
        if col not in df.columns:
            df[col] = [empty() for _ in range(len(df))]
        else:
            df[col] = [
                v if isinstance(v, (list, dict)) else empty()
                for v in df[col]
            ]
    return df
