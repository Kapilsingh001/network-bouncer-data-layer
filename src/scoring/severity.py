"""Severity scoring and classification for the Network Bouncer scoring layer.

Fuses two independent signals into a single, explainable severity:

1. **Rule evidence** (Dev 2)  — ``suspicion_score`` / ``rule_hits``.
2. **Statistical evidence** (Dev 3) — ``outlier_score`` / ``n_anomaly_indicators``
   / ``max_zscore``.

The result is a 0..100 ``severity_score`` and a ``severity_level`` of
None / Low / Medium / High / Critical, plus a human-readable explanation of
exactly which factors drove the score — so an analyst always knows WHY a host
landed where it did.

Scoring model (points-based, deliberately simple and auditable)
---------------------------------------------------------------
    rule_points    = min(suspicion_score * rule_weight, rule_points_cap)
    anomaly_points = min(n_indicators * anomaly_indicator_points
                         + max(0, max_zscore - z_threshold) * zscore_points,
                         anomaly_points_cap)
    severity_score = min(rule_points + anomaly_points, score_cap)

Escalation: a rule-flagged host with >= critical_min_indicators statistical
anomalies is promoted straight to Critical (independent corroboration).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from src.scoring.config import ScoringConfig
from src.utils.logger import get_logger

logger = get_logger(__name__)

SEVERITY_COLUMNS = ["severity_score", "severity_level", "severity_explanation"]

# Ordered for comparison / sorting if needed downstream.
SEVERITY_ORDER = ["None", "Low", "Medium", "High", "Critical"]


@dataclass
class SeverityResult:
    """Per-host severity decision with its justification."""

    srcip: str
    severity_score: float
    severity_level: str
    severity_explanation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "srcip": self.srcip,
            "severity_score": self.severity_score,
            "severity_level": self.severity_level,
            "severity_explanation": list(self.severity_explanation),
        }


class SeverityClassifier:
    """Combine rule + statistical evidence into an explainable severity."""

    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or ScoringConfig()

    # ------------------------------------------------------------------ #
    def classify_row(self, row: pd.Series) -> SeverityResult:
        """Classify a single host row (must hold rule + anomaly fields)."""
        cfg = self.config

        suspicion_score = _get(row, "suspicion_score", 0.0)
        rule_hits = int(_get(row, "rule_hits", 0))
        is_suspicious = bool(_get(row, "is_suspicious", False))
        n_indicators = int(_get(row, "n_anomaly_indicators", 0))
        max_zscore = _get(row, "max_zscore", 0.0)

        rule_points = min(suspicion_score * cfg.rule_weight, cfg.rule_points_cap)
        anomaly_points = min(
            n_indicators * cfg.anomaly_indicator_points
            + max(0.0, max_zscore - cfg.z_threshold) * cfg.zscore_points,
            cfg.anomaly_points_cap,
        )
        severity_score = round(min(rule_points + anomaly_points, cfg.score_cap), 1)

        level = self._to_level(severity_score, is_suspicious, n_indicators)
        explanation = self._explain(
            row, rule_points, anomaly_points, is_suspicious, rule_hits, n_indicators
        )
        return SeverityResult(
            srcip=row["srcip"],
            severity_score=severity_score,
            severity_level=level,
            severity_explanation=explanation,
        )

    # ------------------------------------------------------------------ #
    def classify(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append :data:`SEVERITY_COLUMNS` to a host table."""
        if df is None or df.empty:
            return pd.DataFrame(columns=["srcip", *SEVERITY_COLUMNS])

        results = [self.classify_row(row) for _, row in df.iterrows()]
        return pd.DataFrame([r.to_dict() for r in results])

    # ------------------------------------------------------------------ #
    def _to_level(self, score: float, is_suspicious: bool, n_indicators: int) -> str:
        cfg = self.config
        # Corroborated escalation: rules fired AND multiple statistical anomalies.
        if is_suspicious and n_indicators >= cfg.critical_min_indicators:
            return "Critical"
        if score >= cfg.critical_threshold:
            return "Critical"
        if score >= cfg.high_threshold:
            return "High"
        if score >= cfg.medium_threshold:
            return "Medium"
        if score > 0:
            return "Low"
        return "None"

    def _explain(
        self,
        row: pd.Series,
        rule_points: float,
        anomaly_points: float,
        is_suspicious: bool,
        rule_hits: int,
        n_indicators: int,
    ) -> list[str]:
        reasons: list[str] = []

        if is_suspicious and rule_hits:
            triggered = _get(row, "triggered_rules", [])
            names = ", ".join(triggered) if isinstance(triggered, list) else str(triggered)
            reasons.append(
                f"Rule-based detection: {rule_hits} rule(s) fired"
                + (f" ({names})" if names else "")
            )

        indicators = _get(row, "anomaly_indicators", [])
        if isinstance(indicators, list):
            for ind in indicators:
                reasons.append(f"Statistical outlier: {ind}")

        if n_indicators >= self.config.critical_min_indicators:
            reasons.append(
                f"Multiple statistical anomaly indicators ({n_indicators} features)"
            )

        if rule_points > 0 and anomaly_points > 0:
            reasons.append(
                "Corroborated by both rule-based and statistical evidence"
            )

        if not reasons:
            reasons.append("No detection signal; classified as baseline/normal")
        return reasons


# --------------------------------------------------------------------------- #
def _get(row: pd.Series, key: str, default):
    """Row accessor tolerant of missing columns."""
    try:
        value = row[key]
    except (KeyError, IndexError):
        return default
    if value is None:
        return default
    # Avoid treating NaN scalars as valid numbers.
    if isinstance(value, float) and pd.isna(value):
        return default
    return value
