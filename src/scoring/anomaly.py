"""Statistical anomaly detection for the Network Bouncer scoring layer.

Treats the per-host feature matrix as a *population* and finds hosts that
deviate sharply from the norm using classic statistics — mean, standard
deviation and the one-sided z-score. A host is an outlier on a feature when it
sits ``z_threshold`` standard deviations or more above the population mean.

Why one-sided (high only)?
--------------------------
For every feature we test, the *high* end is the suspicious one (more
connections, more destinations, more ports, more failures). A host far *below*
the mean is quiet, not threatening, so we only flag positive deviations.

SOC-tool shape
--------------
The detector follows a ``fit`` / ``transform`` shape so that, in a real
monitoring tool, a baseline can be learned from historical "known-good" traffic
and then applied to new data. In batch mode, :func:`detect_anomalies` fits and
transforms the same dataset in one call.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from src.scoring.config import ScoringConfig
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Columns this layer appends to the host table.
ANOMALY_COLUMNS = [
    "outlier_score",
    "max_zscore",
    "n_anomaly_indicators",
    "anomaly_indicators",
    "feature_zscores",
]


@dataclass
class AnomalyResult:
    """Per-host statistical anomaly summary."""

    srcip: str
    outlier_score: float
    max_zscore: float
    n_anomaly_indicators: int
    anomaly_indicators: list[str] = field(default_factory=list)
    feature_zscores: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "srcip": self.srcip,
            "outlier_score": self.outlier_score,
            "max_zscore": self.max_zscore,
            "n_anomaly_indicators": self.n_anomaly_indicators,
            "anomaly_indicators": list(self.anomaly_indicators),
            "feature_zscores": dict(self.feature_zscores),
        }


class StatisticalAnomalyDetector:
    """Mean/std/z-score outlier detector over the host feature matrix."""

    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or ScoringConfig()
        self._baseline: dict[str, tuple[float, float]] = {}
        self._fitted = False

    # ------------------------------------------------------------------ #
    def fit(self, feature_matrix: pd.DataFrame) -> "StatisticalAnomalyDetector":
        """Learn the (mean, std) baseline for each configured feature."""
        self._baseline = {}
        if feature_matrix is None or feature_matrix.empty:
            self._fitted = True
            return self

        for feature in self.config.anomaly_features:
            if feature in feature_matrix.columns:
                col = pd.to_numeric(feature_matrix[feature], errors="coerce")
                mean = float(col.mean())
                # Population std (ddof=0); 0 when all hosts share a value.
                std = float(col.std(ddof=0))
                self._baseline[feature] = (mean, std)
        self._fitted = True
        logger.info("Anomaly baseline fitted over %d feature(s)", len(self._baseline))
        return self

    # ------------------------------------------------------------------ #
    def transform(self, feature_matrix: pd.DataFrame) -> pd.DataFrame:
        """Score each host against the fitted baseline.

        Returns
        -------
        pandas.DataFrame
            ``srcip`` plus the :data:`ANOMALY_COLUMNS`.
        """
        if not self._fitted:
            raise RuntimeError("StatisticalAnomalyDetector.transform called before fit().")

        if feature_matrix is None or feature_matrix.empty:
            return pd.DataFrame(columns=["srcip", *ANOMALY_COLUMNS])

        n_hosts = len(feature_matrix)
        # Too few hosts for a trustworthy baseline -> emit neutral results.
        if n_hosts < self.config.min_population:
            logger.warning(
                "Only %d host(s) (< min_population=%d); skipping statistical outlier "
                "detection — severity will rest on rule evidence alone.",
                n_hosts, self.config.min_population,
            )
            return self._neutral_frame(feature_matrix)

        results = [self._score_host(row) for _, row in feature_matrix.iterrows()]
        return pd.DataFrame([r.to_dict() for r in results])

    # ------------------------------------------------------------------ #
    def _score_host(self, row: pd.Series) -> AnomalyResult:
        zscores: dict[str, float] = {}
        indicators: list[str] = []
        outlier_sum = 0.0
        max_z = 0.0

        for feature, (mean, std) in self._baseline.items():
            if feature not in row.index:
                continue
            value = _safe_float(row[feature])
            z = 0.0 if std == 0 or np.isnan(std) else (value - mean) / std
            z = round(float(z), 2)
            zscores[feature] = z
            if z > max_z:
                max_z = z
            if z >= self.config.z_threshold:
                outlier_sum += z
                indicators.append(
                    f"{feature} = {value:g} ({z:.1f}sigma above mean {mean:.2f})"
                )

        return AnomalyResult(
            srcip=row["srcip"],
            outlier_score=round(outlier_sum, 2),
            max_zscore=round(max_z, 2),
            n_anomaly_indicators=len(indicators),
            anomaly_indicators=indicators,
            feature_zscores=zscores,
        )

    def _neutral_frame(self, feature_matrix: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "srcip": feature_matrix["srcip"].tolist(),
                "outlier_score": 0.0,
                "max_zscore": 0.0,
                "n_anomaly_indicators": 0,
                "anomaly_indicators": [[] for _ in range(len(feature_matrix))],
                "feature_zscores": [{} for _ in range(len(feature_matrix))],
            }
        )


def detect_anomalies(
    feature_matrix: pd.DataFrame,
    config: ScoringConfig | None = None,
) -> pd.DataFrame:
    """Batch convenience: fit and transform on the same host matrix."""
    detector = StatisticalAnomalyDetector(config=config)
    return detector.fit(feature_matrix).transform(feature_matrix)


# --------------------------------------------------------------------------- #
def _safe_float(value) -> float:
    try:
        if pd.isna(value):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0
