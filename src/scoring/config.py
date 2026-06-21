"""Scoring configuration for the Network Bouncer statistical + severity layer.

All tunable thresholds for anomaly detection and severity classification live
here in one immutable, documented place — the "scoring policy". A SOC analyst
can tune sensitivity without touching the detection logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Per-host features tested for statistical outliers. Chosen so that a HIGH value
# is the suspicious direction (more volume / more diversity / more failure),
# which lets us use a one-sided z-score. Features where "high" is benign (e.g.
# conn_per_destination, which is high for ordinary busy servers) are excluded.
DEFAULT_ANOMALY_FEATURES: tuple[str, ...] = (
    "total_connections",
    "unique_destinations",
    "unique_dst_ports",
    "unique_src_ports",
    "unique_protocols",
    "unique_services",
    "ports_per_destination",
    "dst_port_ratio",
    "dst_ratio",
    "null_service_ratio",
    "incomplete_ratio",
)


@dataclass(frozen=True)
class ScoringConfig:
    """Immutable policy for statistical anomaly detection and severity scoring.

    Attributes
    ----------
    anomaly_features:
        Numeric feature columns to test for outliers.
    z_threshold:
        A host is an outlier on a feature when its one-sided z-score
        ``(x - mean) / std`` meets or exceeds this many standard deviations.
    min_population:
        Minimum number of hosts required before a statistical baseline is
        meaningful. Below this, anomaly detection is skipped (severity then
        rests on rule evidence alone) to avoid spurious z-scores on tiny samples.
    rule_weight:
        Severity points contributed per unit of Dev 2 ``suspicion_score``.
    rule_points_cap:
        Maximum severity points the rule signal alone can contribute.
    anomaly_indicator_points:
        Severity points per anomalous feature.
    zscore_points:
        Severity points per standard deviation of the host's max z-score above
        ``z_threshold``.
    anomaly_points_cap:
        Maximum severity points the statistical signal alone can contribute.
    score_cap:
        Maximum possible severity score (0..score_cap scale).
    medium_threshold / high_threshold / critical_threshold:
        Severity-score cut-points for the Low/Medium/High/Critical tiers.
    critical_min_indicators:
        A rule-flagged host with at least this many statistical anomaly
        indicators is escalated straight to Critical (corroborated evidence).
    """

    anomaly_features: tuple[str, ...] = DEFAULT_ANOMALY_FEATURES
    z_threshold: float = 3.0
    min_population: int = 5

    # Severity scoring weights (points-based, 0..score_cap).
    rule_weight: float = 5.0
    rule_points_cap: float = 50.0
    anomaly_indicator_points: float = 10.0
    zscore_points: float = 2.0
    anomaly_points_cap: float = 50.0
    score_cap: float = 100.0

    # Severity tier cut-points.
    medium_threshold: float = 25.0
    high_threshold: float = 50.0
    critical_threshold: float = 75.0
    critical_min_indicators: int = 3

    def __post_init__(self) -> None:
        # Defensive validation — fail fast on a nonsensical policy.
        if not (0 < self.medium_threshold < self.high_threshold < self.critical_threshold):
            raise ValueError(
                "Severity thresholds must satisfy 0 < medium < high < critical."
            )
        if self.z_threshold <= 0:
            raise ValueError("z_threshold must be positive.")
