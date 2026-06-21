"""Rule-based detection engine for Network Bouncer.

Runs the rule set (:data:`src.detection.rules.DEFAULT_RULES`) over the
per-host behavioural feature matrix and produces an explainable verdict for
every source host:

* **which** hosts are suspicious,
* **why** (the indicator string for every rule that fired),
* **which** behavioural categories were involved,
* a relative **suspicion score** (sum of fired-rule weights).

Formal severity scoring, dashboards and reporting are owned by other team
members; this engine produces the structured, explainable evidence they build on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from src.detection.config import DetectionConfig
from src.detection.rules import DEFAULT_RULES, Rule
from src.features.feature_builder import build_host_feature_matrix
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Columns the detector appends to the feature matrix.
VERDICT_COLUMNS = [
    "is_suspicious",
    "classification",
    "severity",
    "suspicion_score",
    "rule_hits",
    "triggered_rules",
    "scan_categories",
    "reasons",
]


@dataclass
class HostVerdict:
    """The detector's explainable decision for a single source host."""

    srcip: str
    is_suspicious: bool
    classification: str
    severity: str
    suspicion_score: float
    rule_hits: int
    triggered_rules: list[str] = field(default_factory=list)
    scan_categories: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "srcip": self.srcip,
            "is_suspicious": self.is_suspicious,
            "classification": self.classification,
            "severity": self.severity,
            "suspicion_score": self.suspicion_score,
            "rule_hits": self.rule_hits,
            "triggered_rules": list(self.triggered_rules),
            "scan_categories": list(self.scan_categories),
            "reasons": list(self.reasons),
        }


class RuleBasedDetector:
    """Applies a configurable set of rules to a host feature matrix."""

    def __init__(
        self,
        config: DetectionConfig | None = None,
        rules: list[Rule] | None = None,
    ) -> None:
        self.config = config or DetectionConfig()
        # Copy the default list so callers can't mutate shared state.
        self.rules = list(rules) if rules is not None else list(DEFAULT_RULES)

    # ------------------------------------------------------------------ #
    # Single-host evaluation
    # ------------------------------------------------------------------ #
    def evaluate_host(self, row: pd.Series) -> HostVerdict:
        """Evaluate every rule against one host's feature row."""
        results = [rule.evaluate(row, self.config) for rule in self.rules]
        fired = [r for r in results if r.triggered]

        score = round(sum(r.weight for r in fired), 3)
        is_suspicious = len(fired) >= self.config.min_rules_to_flag
        return HostVerdict(
            srcip=row["srcip"],
            is_suspicious=is_suspicious,
            classification=self._classify(is_suspicious),
            severity=self._severity(is_suspicious, score),
            suspicion_score=score,
            rule_hits=len(fired),
            triggered_rules=[r.rule for r in fired],
            scan_categories=sorted({r.category for r in fired}),
            reasons=[r.indicator for r in fired],
        )

    def _classify(self, is_suspicious: bool) -> str:
        """Map the boolean verdict to the required classification label."""
        return self.config.suspicious_label if is_suspicious else self.config.normal_label

    def _severity(self, is_suspicious: bool, score: float) -> str:
        """Derive a Low/Medium/High triage tier from the suspicion score."""
        if not is_suspicious:
            return "None"
        if score >= self.config.severity_high_score:
            return "High"
        if score >= self.config.severity_medium_score:
            return "Medium"
        return "Low"

    # ------------------------------------------------------------------ #
    # Matrix-level detection
    # ------------------------------------------------------------------ #
    def detect(self, feature_matrix: pd.DataFrame) -> pd.DataFrame:
        """Run detection over a feature matrix.

        Returns the feature matrix with the :data:`VERDICT_COLUMNS` appended,
        sorted so the most suspicious hosts surface first.
        """
        if feature_matrix is None or feature_matrix.empty:
            logger.warning("detect() received an empty feature matrix")
            return _empty_result(feature_matrix)

        verdicts = [self.evaluate_host(row) for _, row in feature_matrix.iterrows()]

        result = feature_matrix.copy()
        result["is_suspicious"] = [v.is_suspicious for v in verdicts]
        result["classification"] = [v.classification for v in verdicts]
        result["severity"] = [v.severity for v in verdicts]
        result["suspicion_score"] = [v.suspicion_score for v in verdicts]
        result["rule_hits"] = [v.rule_hits for v in verdicts]
        result["triggered_rules"] = [v.triggered_rules for v in verdicts]
        result["scan_categories"] = [v.scan_categories for v in verdicts]
        result["reasons"] = [v.reasons for v in verdicts]

        result = result.sort_values(
            ["is_suspicious", "suspicion_score", "rule_hits"],
            ascending=False,
            ignore_index=True,
        )
        flagged = int(result["is_suspicious"].sum())
        logger.info("Detection complete: %d/%d host(s) flagged suspicious", flagged, len(result))
        return result

    def detect_from_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convenience: build features from cleaned flows, then detect."""
        matrix = build_host_feature_matrix(df, self.config.established_states)
        return self.detect(matrix)

    # ------------------------------------------------------------------ #
    # Alert extraction
    # ------------------------------------------------------------------ #
    def alerts(self, result: pd.DataFrame) -> list[dict]:
        """Return JSON-ready alert dicts for the suspicious hosts only."""
        if result is None or result.empty or "is_suspicious" not in result.columns:
            return []
        suspicious = result[result["is_suspicious"]]
        return [_row_to_alert(row) for _, row in suspicious.iterrows()]


# --------------------------------------------------------------------------- #
# Module-level convenience API
# --------------------------------------------------------------------------- #
def detect_scanning(
    df: pd.DataFrame,
    config: DetectionConfig | None = None,
) -> pd.DataFrame:
    """One-shot helper: cleaned flows -> per-host detection result table.

    This is the primary integration entry point for the rest of the team::

        from src.detection import detect_scanning
        result = detect_scanning(clean_df)
    """
    detector = RuleBasedDetector(config=config)
    return detector.detect_from_flows(df)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _empty_result(feature_matrix: pd.DataFrame | None) -> pd.DataFrame:
    base_cols = list(feature_matrix.columns) if feature_matrix is not None else []
    return pd.DataFrame(columns=base_cols + VERDICT_COLUMNS)


def _row_to_alert(row: pd.Series) -> dict:
    """Shape a result row into a self-contained alert record."""
    return {
        "srcip": row["srcip"],
        "classification": row["classification"],
        "severity": row["severity"],
        "suspicion_score": float(row["suspicion_score"]),
        "rule_hits": int(row["rule_hits"]),
        "scan_categories": list(row["scan_categories"]),
        "triggered_rules": list(row["triggered_rules"]),
        "reasons": list(row["reasons"]),
        "evidence": {
            "total_connections": int(row["total_connections"]),
            "unique_destinations": int(row["unique_destinations"]),
            "unique_dst_ports": int(row["unique_dst_ports"]),
            "ports_per_destination": float(row["ports_per_destination"]),
            "conn_per_destination": float(row["conn_per_destination"]),
            "dst_port_ratio": float(row["dst_port_ratio"]),
            "null_service_ratio": float(row["null_service_ratio"]),
            "incomplete_ratio": float(row["incomplete_ratio"]),
        },
    }
